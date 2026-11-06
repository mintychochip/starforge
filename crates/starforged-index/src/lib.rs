//! starforged-index: the tantivy search index (spec §10.5, plan M4a).
//!
//! The only crate that depends on tantivy. It has no database access:
//! `starforged-core` feeds it plain [`TrailDoc`]s and [`EventDoc`]s built from
//! rows and blob contents. The index is never the source of truth — callers
//! re-read and re-check every hit against the database before returning it
//! (plan D3) — a stale document can only hide a result, never leak one.
//!
//! Schema (plan D2): one index, `doc_kind` ∈ {`trail`, `event`}. Trail docs
//! carry the title plus intent and comment bodies; event docs carry message
//! text, tool names, and file paths only (never tool inputs or outputs).
//!
//! Mutations (`replace_*`, `drop_*`, [`SearchIndex::clear`]) are staged on the
//! writer behind a mutex and become visible at [`SearchIndex::commit`], which
//! reloads the reader. [`SearchIndex::open_or_create`] recreates a missing or
//! corrupt directory empty instead of failing, so the server never refuses to
//! start because of the index (plan D5). When another process already holds
//! the writer (the server is running), the writer cannot be opened and the
//! call reports [`IndexError::Locked`] — the caller must stop the server or
//! use the site-admin rebuild action.

use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, RwLock};

use tantivy::collector::{Count, TopDocs};
use tantivy::query::{AllQuery, BooleanQuery, Occur, Query, RangeQuery, RegexQuery, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, NumericOptions, STORED, Schema, TEXT, TextFieldIndexing, TextOptions,
    Value,
};
use tantivy::{Index, IndexReader, IndexWriter, Order, TantivyDocument, TantivyError, Term};

/// The default commit heap for the index writer.
const WRITER_HEAP_BYTES: usize = 50_000_000;
/// Snippet length cap, in characters.
const SNIPPET_CHARS: usize = 500;

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error(
        "the search index is in use: stop the server and retry, or use the site-admin rebuild action ({0})"
    )]
    Locked(String),
    #[error("the search index on disk does not match the current schema")]
    Corrupt,
    #[error(transparent)]
    Tantivy(#[from] TantivyError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("the search index writer lock is poisoned")]
    Poisoned,
}

/// The index's `Result`, with [`IndexError`] as the default error type.
pub type Result<T, E = IndexError> = std::result::Result<T, E>;
/// One Trail: its title plus intent and comment bodies as the searchable text.
#[derive(Debug, Clone)]
pub struct TrailDoc {
    pub trail_id: i64,
    pub repo_id: i64,
    /// `public`, `internal`, or `private` (the repository's visibility).
    pub repo_visibility: &'static str,
    pub title: String,
    /// The intent and all comment bodies.
    pub body: String,
    pub author_id: Option<i64>,
    pub state: String,
    /// `updated_at` (plan D4).
    pub ts: i64,
}

/// One session event that has searchable content: message text, a tool name,
/// or a file path. Tool inputs and outputs never land here (plan D2).
#[derive(Debug, Clone)]
pub struct EventDoc {
    pub session_id: i64,
    pub seq: i64,
    pub repo_id: i64,
    /// `public`, `internal`, or `private` (the repository's visibility).
    pub repo_visibility: &'static str,
    pub text: String,
    pub agent: String,
    pub models: Vec<String>,
    pub uploader_id: i64,
    pub published: bool,
    pub quarantined: bool,
    /// The session's linked commit SHAs, from `commit_links`.
    pub commits: Vec<String>,
    /// The event's own timestamp (plan D4).
    pub ts: i64,
}

/// The viewer the permission filter (plan D3) is built for.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// Whether the viewer is signed in (internal repositories need it).
    pub signed_in: bool,
    /// Private and internal repositories the viewer can read (explicit
    /// grants, org and team grants, or all repositories for site admins).
    pub readable: Vec<i64>,
    /// Repositories where the viewer is a member (publication clause).
    pub member: Vec<i64>,
    /// Repositories where the viewer is a repo admin (quarantine clause).
    pub admin: Vec<i64>,
    /// The viewer, for the uploader clause of the quarantine rule.
    pub viewer_id: Option<i64>,
}

/// Trail search filters (plan D4).
#[derive(Debug, Clone, Default)]
pub struct TrailQuery {
    pub q: String,
    pub repo_id: Option<i64>,
    pub author_id: Option<i64>,
    pub from: Option<i64>,
    pub to: Option<i64>,
}

/// Session event search filters (plan D4).
#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub q: String,
    pub repo_id: Option<i64>,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub author_id: Option<i64>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    /// A full or ≥7-character SHA prefix, matched against `commits`.
    pub commit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailHit {
    pub trail_id: i64,
    pub repo_id: i64,
    pub title: String,
    pub state: String,
    pub ts: i64,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventHit {
    pub session_id: i64,
    pub seq: i64,
    pub repo_id: i64,
    pub ts: i64,
    pub snippet: String,
}

/// Document counts per kind, for the doctor and `index rebuild` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexStats {
    pub trails: u64,
    pub events: u64,
}

#[derive(Clone, Copy)]
struct Fields {
    doc_kind: Field,
    repo_id: Field,
    repo_visibility: Field,
    ts: Field,
    trail_id: Field,
    title: Field,
    body: Field,
    author_id: Field,
    state: Field,
    session_id: Field,
    seq: Field,
    text: Field,
    agent: Field,
    models: Field,
    uploader_id: Field,
    published: Field,
    quarantined: Field,
    commits: Field,
}

/// The index schema (plan D2): exact-match string fields use the `raw`
/// tokenizer so term queries match whole values; free text uses the default
/// tokenizer and is stored for snippets.
fn build_schema() -> (Schema, Fields) {
    let mut builder = Schema::builder();
    let keyword = || {
        TextOptions::default().set_indexing_options(
            TextFieldIndexing::default()
                .set_index_option(IndexRecordOption::Basic)
                .set_tokenizer("raw"),
        )
    };
    let number = || {
        NumericOptions::default()
            .set_fast()
            .set_indexed()
            .set_stored()
    };
    let fields = Fields {
        doc_kind: builder.add_text_field("doc_kind", keyword()),
        repo_id: builder.add_i64_field("repo_id", number()),
        repo_visibility: builder.add_text_field("repo_visibility", keyword()),
        ts: builder.add_i64_field("ts", number()),
        trail_id: builder.add_i64_field("trail_id", number()),
        title: builder.add_text_field("title", TEXT | STORED),
        body: builder.add_text_field("body", TEXT | STORED),
        author_id: builder.add_i64_field("author_id", number()),
        state: builder.add_text_field("state", keyword().set_stored()),
        session_id: builder.add_i64_field("session_id", number()),
        seq: builder.add_i64_field("seq", number()),
        text: builder.add_text_field("text", TEXT | STORED),
        agent: builder.add_text_field("agent", keyword()),
        models: builder.add_text_field("models", keyword()),
        uploader_id: builder.add_i64_field("uploader_id", number()),
        published: builder.add_i64_field("published", number()),
        quarantined: builder.add_i64_field("quarantined", number()),
        commits: builder.add_text_field("commits", keyword()),
    };
    (builder.build(), fields)
}

/// The tantivy search index: one writer behind a mutex, one reader that
/// reloads on commit. Cheap to share behind an `Arc`.
pub struct SearchIndex {
    dir: PathBuf,
    fields: Fields,
    writer: Mutex<IndexWriter>,
    reader: RwLock<IndexReader>,
}

impl std::fmt::Debug for SearchIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchIndex")
            .field("dir", &self.dir)
            .finish()
    }
}

impl SearchIndex {
    /// Opens the index in `dir`, creating it if missing. A directory that is
    /// present but not a readable index of the current schema is recreated
    /// empty (the index is never the source of truth). When another process
    /// holds the writer — the server is running — the writer cannot be
    /// opened and the caller gets [`IndexError::Locked`]; the directory is
    /// left untouched in that case.
    pub fn open_or_create(dir: &Path) -> Result<Self> {
        match Self::try_open(dir) {
            Err(IndexError::Locked(_)) => Err(IndexError::Locked(format!(
                "cannot acquire the writer at {}",
                dir.display()
            ))),
            Err(_) => Self::create(dir),
            Ok(index) => Ok(index),
        }
    }

    fn try_open(dir: &Path) -> Result<Self> {
        let (schema, fields) = build_schema();
        let index = Index::open_in_dir(dir)?;
        if index.schema() != schema {
            return Err(IndexError::Corrupt);
        }
        Self::from_index(dir.to_path_buf(), index, fields)
    }

    fn create(dir: &Path) -> Result<Self> {
        let (schema, fields) = build_schema();
        // Whatever is there is not a readable index: rebuild it empty rather
        // than fail the caller (startup contract, plan D5).
        if std::fs::remove_dir_all(dir).is_err() {
            let _ = std::fs::remove_file(dir);
        }
        std::fs::create_dir_all(dir)?;
        let index = Index::create_in_dir(dir, schema)?;
        Self::from_index(dir.to_path_buf(), index, fields)
    }

    fn from_index(dir: PathBuf, index: Index, fields: Fields) -> Result<Self> {
        let writer = index
            .writer(WRITER_HEAP_BYTES)
            .map_err(|err| IndexError::Locked(err.to_string()))?;
        let reader = index.reader().map_err(IndexError::Tantivy)?;
        Ok(SearchIndex {
            dir,
            fields,
            writer: Mutex::new(writer),
            reader: RwLock::new(reader),
        })
    }

    fn writer(&self) -> Result<MutexGuard<'_, IndexWriter>> {
        self.writer.lock().map_err(|_| IndexError::Poisoned)
    }

    /// Removes every document, then callers re-add and [`SearchIndex::commit`]
    /// once (the rebuild path).
    pub fn clear(&self) -> Result<()> {
        self.writer()?.delete_all_documents()?;
        Ok(())
    }

    /// Replaces the Trail's document (delete by `trail_id`, then insert).
    pub fn replace_trail(&self, doc: TrailDoc) -> Result<()> {
        let writer = self.writer()?;
        writer.delete_term(Term::from_field_i64(self.fields.trail_id, doc.trail_id));
        writer.add_document(self.trail_document(&doc))?;
        Ok(())
    }

    /// Replaces every event document of the session (delete by `session_id`,
    /// then insert `docs`).
    pub fn replace_session(&self, session_id: i64, docs: Vec<EventDoc>) -> Result<()> {
        let writer = self.writer()?;
        writer.delete_term(Term::from_field_i64(self.fields.session_id, session_id));
        for doc in &docs {
            writer.add_document(self.event_document(doc))?;
        }
        Ok(())
    }

    /// Removes every event document of the session (delete or purge).
    pub fn drop_session(&self, session_id: i64) -> Result<()> {
        let writer = self.writer()?;
        writer.delete_term(Term::from_field_i64(self.fields.session_id, session_id));
        Ok(())
    }

    /// Removes every document of the repository (delete or purge).
    pub fn drop_repo(&self, repo_id: i64) -> Result<()> {
        let writer = self.writer()?;
        writer.delete_term(Term::from_field_i64(self.fields.repo_id, repo_id));
        Ok(())
    }

    /// Commits the staged documents and reloads the reader, so the next
    /// search sees them.
    pub fn commit(&self) -> Result<()> {
        self.writer()?.commit()?;
        self.reader
            .write()
            .map_err(|_| IndexError::Poisoned)?
            .reload()?;
        Ok(())
    }

    /// Document counts per kind.
    pub fn stats(&self) -> Result<IndexStats> {
        let reader = self.reader.read().map_err(|_| IndexError::Poisoned)?;
        reader.reload()?;
        let searcher = reader.searcher();
        let trails = searcher.search(&term_query(self.fields.doc_kind, "trail"), &Count)?;
        let events = searcher.search(&term_query(self.fields.doc_kind, "event"), &Count)?;
        Ok(IndexStats {
            trails: trails as u64,
            events: events as u64,
        })
    }

    pub fn search_trails(
        &self,
        q: &TrailQuery,
        scope: &Scope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<TrailHit>> {
        let query = self.trail_query(q, scope)?;
        let docs = self.top_docs(&query, offset, limit)?;
        docs.iter()
            .map(|doc| {
                let f = self.fields;
                Ok(TrailHit {
                    trail_id: doc_i64(doc, f.trail_id),
                    repo_id: doc_i64(doc, f.repo_id),
                    title: doc_str(doc, f.title).unwrap_or_default().to_owned(),
                    state: doc_str(doc, f.state).unwrap_or_default().to_owned(),
                    ts: doc_i64(doc, f.ts),
                    snippet: snippet(doc_str(doc, f.body).unwrap_or_default()),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    pub fn search_events(
        &self,
        q: &EventQuery,
        scope: &Scope,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<EventHit>> {
        let query = self.event_query(q, scope)?;
        let docs = self.top_docs(&query, offset, limit)?;
        docs.iter()
            .map(|doc| {
                let f = self.fields;
                Ok(EventHit {
                    session_id: doc_i64(doc, f.session_id),
                    seq: doc_i64(doc, f.seq),
                    repo_id: doc_i64(doc, f.repo_id),
                    ts: doc_i64(doc, f.ts),
                    snippet: snippet(doc_str(doc, f.text).unwrap_or_default()),
                })
            })
            .collect::<Result<Vec<_>>>()
    }

    /// The top `limit` documents after `offset`, newest `ts` first, matching
    /// `query`.
    fn top_docs(
        &self,
        query: &BooleanQuery,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<TantivyDocument>> {
        let reader = self.reader.read().map_err(|_| IndexError::Poisoned)?;
        reader.reload()?;
        let searcher = reader.searcher();
        let collector = TopDocs::with_limit(limit)
            .and_offset(offset)
            .order_by_fast_field::<i64>("ts", Order::Desc);
        let hits = searcher.search(query, &collector)?;
        hits.into_iter()
            .map(|(_, address)| Ok(searcher.doc::<TantivyDocument>(address)?))
            .collect()
    }

    fn trail_query(&self, q: &TrailQuery, scope: &Scope) -> Result<BooleanQuery> {
        let f = self.fields;
        let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
        if let Some(text) = text_query(&q.q, &[f.title, f.body])? {
            clauses.push((Occur::Must, text));
        }
        clauses.push((
            Occur::Must,
            Box::new(term_query(f.doc_kind, "trail")) as Box<dyn Query>,
        ));
        clauses.push((
            Occur::Must,
            Box::new(self.readable_clause(scope)) as Box<dyn Query>,
        ));
        if let Some(repo_id) = q.repo_id {
            clauses.push((Occur::Must, Box::new(i64_eq(f.repo_id, repo_id))));
        }
        if let Some(author_id) = q.author_id {
            clauses.push((Occur::Must, Box::new(i64_eq(f.author_id, author_id))));
        }
        if q.from.is_some() || q.to.is_some() {
            clauses.push((Occur::Must, Box::new(i64_range(f.ts, q.from, q.to))));
        }
        Ok(BooleanQuery::new(clauses))
    }

    fn event_query(&self, q: &EventQuery, scope: &Scope) -> Result<BooleanQuery> {
        let f = self.fields;
        let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
        if let Some(text) = text_query(&q.q, &[f.text])? {
            clauses.push((Occur::Must, text));
        }
        clauses.push((
            Occur::Must,
            Box::new(term_query(f.doc_kind, "event")) as Box<dyn Query>,
        ));
        clauses.push((
            Occur::Must,
            Box::new(self.readable_clause(scope)) as Box<dyn Query>,
        ));
        // §6.4 publication and quarantine clauses (plan D3).
        clauses.push((
            Occur::Must,
            Box::new(self.publication_clause(scope)) as Box<dyn Query>,
        ));
        clauses.push((
            Occur::Must,
            Box::new(self.quarantine_clause(scope)) as Box<dyn Query>,
        ));
        if let Some(repo_id) = q.repo_id {
            clauses.push((Occur::Must, Box::new(i64_eq(f.repo_id, repo_id))));
        }
        if let Some(agent) = &q.agent {
            clauses.push((Occur::Must, Box::new(term_query(f.agent, agent))));
        }
        if let Some(model) = &q.model {
            clauses.push((Occur::Must, Box::new(term_query(f.models, model))));
        }
        if let Some(author_id) = q.author_id {
            clauses.push((Occur::Must, Box::new(i64_eq(f.uploader_id, author_id))));
        }
        if q.from.is_some() || q.to.is_some() {
            clauses.push((Occur::Must, Box::new(i64_range(f.ts, q.from, q.to))));
        }
        if let Some(commit) = &q.commit {
            clauses.push((Occur::Must, commit_prefix_query(f.commits, commit)?));
        }
        Ok(BooleanQuery::new(clauses))
    }

    /// Repo readability (plan D3): public visibility, or internal and signed
    /// in, or `repo_id` in the viewer's readable set.
    fn readable_clause(&self, scope: &Scope) -> BooleanQuery {
        let f = self.fields;
        let mut arms: Vec<(Occur, Box<dyn Query>)> = vec![(
            Occur::Should,
            Box::new(term_query(f.repo_visibility, "public")) as Box<dyn Query>,
        )];
        if scope.signed_in {
            arms.push((
                Occur::Should,
                Box::new(term_query(f.repo_visibility, "internal")) as Box<dyn Query>,
            ));
        }
        if !scope.readable.is_empty() {
            arms.push((
                Occur::Should,
                Box::new(i64_in(f.repo_id, &scope.readable)) as Box<dyn Query>,
            ));
        }
        BooleanQuery::new(arms)
    }

    /// Publication (plan D3): not public, or published, or a repository where
    /// the viewer is a member. `repo_visibility != public` is the `internal`
    /// or `private` arm (the only other values).
    fn publication_clause(&self, scope: &Scope) -> BooleanQuery {
        let f = self.fields;
        let mut arms: Vec<(Occur, Box<dyn Query>)> = vec![
            (
                Occur::Should,
                Box::new(term_query(f.repo_visibility, "internal")) as Box<dyn Query>,
            ),
            (
                Occur::Should,
                Box::new(term_query(f.repo_visibility, "private")) as Box<dyn Query>,
            ),
            (
                Occur::Should,
                Box::new(i64_eq(f.published, 1)) as Box<dyn Query>,
            ),
        ];
        if !scope.member.is_empty() {
            arms.push((
                Occur::Should,
                Box::new(i64_in(f.repo_id, &scope.member)) as Box<dyn Query>,
            ));
        }
        BooleanQuery::new(arms)
    }

    /// Quarantine (plan D3): not quarantined, or the viewer uploaded the
    /// session, or a repository where the viewer is a repo admin.
    fn quarantine_clause(&self, scope: &Scope) -> BooleanQuery {
        let f = self.fields;
        let mut arms: Vec<(Occur, Box<dyn Query>)> = vec![(
            Occur::Should,
            Box::new(i64_eq(f.quarantined, 0)) as Box<dyn Query>,
        )];
        if let Some(viewer_id) = scope.viewer_id {
            arms.push((
                Occur::Should,
                Box::new(i64_eq(f.uploader_id, viewer_id)) as Box<dyn Query>,
            ));
        }
        if !scope.admin.is_empty() {
            arms.push((
                Occur::Should,
                Box::new(i64_in(f.repo_id, &scope.admin)) as Box<dyn Query>,
            ));
        }
        BooleanQuery::new(arms)
    }

    fn trail_document(&self, doc: &TrailDoc) -> TantivyDocument {
        let f = self.fields;
        let mut document = TantivyDocument::default();
        document.add_text(f.doc_kind, "trail");
        document.add_i64(f.repo_id, doc.repo_id);
        document.add_text(f.repo_visibility, doc.repo_visibility);
        document.add_i64(f.ts, doc.ts);
        document.add_i64(f.trail_id, doc.trail_id);
        document.add_text(f.title, &doc.title);
        document.add_text(f.body, &doc.body);
        if let Some(author_id) = doc.author_id {
            document.add_i64(f.author_id, author_id);
        }
        document.add_text(f.state, &doc.state);
        document
    }

    fn event_document(&self, doc: &EventDoc) -> TantivyDocument {
        let f = self.fields;
        let mut document = TantivyDocument::default();
        document.add_text(f.doc_kind, "event");
        document.add_i64(f.repo_id, doc.repo_id);
        document.add_text(f.repo_visibility, doc.repo_visibility);
        document.add_i64(f.ts, doc.ts);
        document.add_i64(f.session_id, doc.session_id);
        document.add_i64(f.seq, doc.seq);
        document.add_text(f.text, &doc.text);
        document.add_text(f.agent, &doc.agent);
        for model in &doc.models {
            document.add_text(f.models, model);
        }
        document.add_i64(f.uploader_id, doc.uploader_id);
        document.add_i64(f.published, i64::from(doc.published));
        document.add_i64(f.quarantined, i64::from(doc.quarantined));
        for commit in &doc.commits {
            document.add_text(f.commits, commit);
        }
        document
    }
}

fn term_query(field: Field, value: &str) -> TermQuery {
    TermQuery::new(
        Term::from_field_text(field, value),
        IndexRecordOption::Basic,
    )
}

fn i64_eq(field: Field, value: i64) -> RangeQuery {
    i64_range(field, Some(value), Some(value))
}

fn i64_range(field: Field, lower: Option<i64>, upper: Option<i64>) -> RangeQuery {
    let bound = |value: Option<i64>| match value {
        Some(value) => Bound::Included(Term::from_field_i64(field, value)),
        None => Bound::Unbounded,
    };
    RangeQuery::new(bound(lower), bound(upper))
}

/// The `commit` filter: a SHA prefix matched against `commits`. The prefix
/// must be non-empty hex; anything else matches nothing.
fn commit_prefix_query(field: Field, prefix: &str) -> Result<Box<dyn Query>> {
    if !prefix.is_empty() && prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        // Hex digits need no regex escaping. tantivy-fst patterns are
        // implicitly anchored to the whole term, so this is a prefix match.
        Ok(Box::new(RegexQuery::from_pattern(
            &format!("{prefix}.*"),
            field,
        )?))
    } else {
        Ok(Box::new(BooleanQuery::new(vec![(
            Occur::MustNot,
            Box::new(AllQuery) as Box<dyn Query>,
        )])))
    }
}

fn i64_in(field: Field, values: &[i64]) -> BooleanQuery {
    BooleanQuery::new(
        values
            .iter()
            .map(|value| {
                (
                    Occur::Should,
                    Box::new(i64_eq(field, *value)) as Box<dyn Query>,
                )
            })
            .collect(),
    )
}

/// The query-time tokenization mirrors the indexed default tokenizer (unicode
/// lowercase, split on non-alphanumerics) without the parser's syntax, so a
/// query containing tantivy operators still searches as literal words.
fn tokens(q: &str) -> Vec<String> {
    q.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The `q` filter: every query token must appear in one of `fields`. An empty
/// (or punctuation-only) `q` matches nothing; a blank query is spelled by
/// leaving the text clause out entirely.
fn text_query(q: &str, fields: &[Field]) -> Result<Option<Box<dyn Query>>> {
    if q.is_empty() {
        return Ok(None);
    }
    let tokens = tokens(q);
    if tokens.is_empty() {
        return Ok(Some(Box::new(BooleanQuery::new(vec![(
            Occur::MustNot,
            Box::new(AllQuery) as Box<dyn Query>,
        )]))));
    }
    let per_token = tokens
        .into_iter()
        .map(|token| {
            (
                Occur::Must,
                Box::new(BooleanQuery::new(
                    fields
                        .iter()
                        .map(|field| {
                            (
                                Occur::Should,
                                Box::new(term_query(*field, &token)) as Box<dyn Query>,
                            )
                        })
                        .collect(),
                )) as Box<dyn Query>,
            )
        })
        .collect::<Vec<_>>();
    Ok(Some(Box::new(BooleanQuery::new(per_token))))
}

fn doc_i64(doc: &TantivyDocument, field: Field) -> i64 {
    doc.get_first(field)
        .and_then(|value| value.as_i64())
        .unwrap_or(0)
}

fn doc_str(doc: &TantivyDocument, field: Field) -> Option<&str> {
    doc.get_first(field).and_then(|value| value.as_str())
}

fn snippet(text: &str) -> String {
    if text.chars().count() > SNIPPET_CHARS {
        format!("{}…", text.chars().take(SNIPPET_CHARS).collect::<String>())
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        index: SearchIndex,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let index = SearchIndex::open_or_create(dir.path()).unwrap();
        Fixture { _dir: dir, index }
    }

    fn trail(id: i64, repo_id: i64, visibility: &'static str, title: &str, body: &str) -> TrailDoc {
        TrailDoc {
            trail_id: id,
            repo_id,
            repo_visibility: visibility,
            title: title.to_owned(),
            body: body.to_owned(),
            author_id: Some(7),
            state: "open".to_owned(),
            ts: 1_700_000_000,
        }
    }
    fn event(
        session_id: i64,
        seq: i64,
        repo_id: i64,
        visibility: &'static str,
        text: &str,
    ) -> EventDoc {
        EventDoc {
            session_id,
            seq,
            repo_id,
            repo_visibility: visibility,
            text: text.to_owned(),
            agent: "pi".to_owned(),
            models: vec!["m1".to_owned()],
            uploader_id: 7,
            published: true,
            quarantined: false,
            commits: Vec::new(),
            ts: 1_700_000_000,
        }
    }

    fn trail_ids(index: &SearchIndex, q: &TrailQuery, scope: &Scope) -> Vec<i64> {
        index
            .search_trails(q, scope, 0, 20)
            .unwrap()
            .into_iter()
            .map(|hit| hit.trail_id)
            .collect()
    }

    fn event_seqs(index: &SearchIndex, q: &EventQuery, scope: &Scope) -> Vec<(i64, i64)> {
        index
            .search_events(q, scope, 0, 20)
            .unwrap()
            .into_iter()
            .map(|hit| (hit.session_id, hit.seq))
            .collect()
    }

    fn wide() -> Scope {
        Scope {
            signed_in: true,
            readable: vec![1, 2],
            member: vec![1, 2],
            admin: vec![1, 2],
            viewer_id: Some(7),
        }
    }

    #[test]
    fn empty_index_has_no_documents() {
        let f = fixture();
        assert_eq!(
            f.index.stats().unwrap(),
            IndexStats {
                trails: 0,
                events: 0
            }
        );
        assert!(
            f.index
                .search_trails(
                    &TrailQuery {
                        q: "anything".into(),
                        ..Default::default()
                    },
                    &wide(),
                    0,
                    20
                )
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn trails_are_found_by_title_and_body() {
        let f = fixture();
        f.index
            .replace_trail(trail(
                1,
                1,
                "public",
                "Quasar search tweak",
                "the intent mentions zebras",
            ))
            .unwrap();
        f.index
            .replace_trail(trail(2, 1, "public", "Unrelated", "nothing to see"))
            .unwrap();
        f.index.commit().unwrap();
        let scope = Scope::default();
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    q: "quasar".into(),
                    ..Default::default()
                },
                &scope
            ),
            vec![1],
            "title match"
        );
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    q: "zebras".into(),
                    ..Default::default()
                },
                &scope
            ),
            vec![1],
            "body match"
        );
        // Two tokens must both appear (across title and body).
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    q: "quasar zebras".into(),
                    ..Default::default()
                },
                &scope
            ),
            vec![1]
        );
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    q: "quasar missing".into(),
                    ..Default::default()
                },
                &scope
            ),
            Vec::<i64>::new()
        );
    }

    #[test]
    fn events_are_found_by_text_tool_name_and_file_path() {
        let f = fixture();
        f.index
            .replace_session(
                10,
                vec![event(10, 1, 1, "public", "please refactor the widget")],
            )
            .unwrap();
        f.index
            .replace_session(
                10,
                vec![
                    event(10, 1, 1, "public", "plain message"),
                    event(10, 2, 1, "public", "bash"),
                    event(10, 3, 1, "public", "src/main.rs"),
                ],
            )
            .unwrap();
        f.index.commit().unwrap();
        // `replace_session` replaced the first batch: "refactor" is gone.
        let scope = Scope::default();
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    q: "refactor".into(),
                    ..Default::default()
                },
                &scope
            ),
            Vec::<(i64, i64)>::new()
        );
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    q: "plain".into(),
                    ..Default::default()
                },
                &scope
            ),
            vec![(10, 1)]
        );
        // Tool name and file path are ordinary indexed text.
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    q: "bash".into(),
                    ..Default::default()
                },
                &scope
            ),
            vec![(10, 2)]
        );
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    q: "main".into(),
                    ..Default::default()
                },
                &scope
            ),
            vec![(10, 3)],
            "file path tokenizes the same way at index and query time"
        );
    }

    #[test]
    fn trail_filters_narrow_the_results() {
        let f = fixture();
        let mut a = trail(1, 1, "public", "alpha", "body");
        a.author_id = Some(7);
        a.ts = 100;
        let mut b = trail(2, 2, "public", "alpha", "body");
        b.author_id = Some(8);
        b.ts = 200;
        f.index.replace_trail(a).unwrap();
        f.index.replace_trail(b).unwrap();
        f.index.commit().unwrap();
        let scope = wide();
        let all = TrailQuery {
            q: "alpha".into(),
            ..Default::default()
        };
        assert_eq!(trail_ids(&f.index, &all, &scope), vec![2, 1]);
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    repo_id: Some(1),
                    ..all.clone()
                },
                &scope
            ),
            vec![1]
        );
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    author_id: Some(8),
                    ..all.clone()
                },
                &scope
            ),
            vec![2]
        );
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    from: Some(150),
                    ..all.clone()
                },
                &scope
            ),
            vec![2]
        );
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    to: Some(150),
                    ..all.clone()
                },
                &scope
            ),
            vec![1]
        );
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    from: Some(50),
                    to: Some(150),
                    ..all.clone()
                },
                &scope
            ),
            vec![1],
            "inclusive range"
        );
    }

    #[test]
    fn event_filters_narrow_the_results() {
        let f = fixture();
        let mut a = event(10, 1, 1, "public", "shared text");
        a.agent = "pi".to_owned();
        a.models = vec!["m1".to_owned()];
        a.uploader_id = 7;
        a.commits = vec!["deadbee0123456789abcdef".to_owned()];
        let mut b = event(11, 1, 2, "public", "shared text");
        b.agent = "codex".to_owned();
        b.models = vec!["m2".to_owned()];
        b.uploader_id = 8;
        b.commits = vec!["cafef00ddc0ffee".to_owned()];
        f.index.replace_session(10, vec![a]).unwrap();
        f.index.replace_session(11, vec![b]).unwrap();
        f.index.commit().unwrap();
        let scope = wide();
        let all = EventQuery {
            q: "shared".into(),
            ..Default::default()
        };
        assert_eq!(event_seqs(&f.index, &all, &scope).len(), 2);
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    repo_id: Some(1),
                    ..all.clone()
                },
                &scope
            ),
            vec![(10, 1)]
        );
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    agent: Some("pi".into()),
                    ..all.clone()
                },
                &scope
            ),
            vec![(10, 1)]
        );
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    model: Some("m2".into()),
                    ..all.clone()
                },
                &scope
            ),
            vec![(11, 1)]
        );
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    author_id: Some(8),
                    ..all.clone()
                },
                &scope
            ),
            vec![(11, 1)]
        );
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    commit: Some("deadbee".into()),
                    ..all.clone()
                },
                &scope
            ),
            vec![(10, 1)],
            "a SHA prefix matches the commit"
        );
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    commit: Some("deadbeex".into()),
                    ..all.clone()
                },
                &scope
            ),
            Vec::<(i64, i64)>::new()
        );
    }

    #[test]
    fn private_documents_need_the_repo_in_readable() {
        let f = fixture();
        f.index
            .replace_trail(trail(1, 9, "private", "secret plans", "hidden"))
            .unwrap();
        f.index.commit().unwrap();
        let search = |scope: &Scope| {
            trail_ids(
                &f.index,
                &TrailQuery {
                    q: "secret".into(),
                    ..Default::default()
                },
                scope,
            )
        };
        assert_eq!(search(&Scope::default()), Vec::<i64>::new());
        assert_eq!(
            search(&Scope {
                signed_in: true,
                viewer_id: Some(3),
                ..Default::default()
            }),
            Vec::<i64>::new(),
            "signing in does not open a private repository"
        );
        assert_eq!(
            search(&Scope {
                readable: vec![9],
                ..Default::default()
            }),
            vec![1]
        );
    }

    #[test]
    fn internal_documents_need_a_signed_in_viewer() {
        let f = fixture();
        f.index
            .replace_trail(trail(1, 9, "internal", "internal plans", "hidden"))
            .unwrap();
        f.index.commit().unwrap();
        let search = |scope: &Scope| {
            trail_ids(
                &f.index,
                &TrailQuery {
                    q: "internal".into(),
                    ..Default::default()
                },
                scope,
            )
        };
        assert_eq!(search(&Scope::default()), Vec::<i64>::new());
        assert_eq!(
            search(&Scope {
                signed_in: true,
                viewer_id: Some(3),
                ..Default::default()
            }),
            vec![1]
        );
    }

    #[test]
    fn public_unpublished_events_need_membership() {
        let f = fixture();
        let mut doc = event(10, 1, 9, "public", "draft notes");
        doc.published = false;
        f.index.replace_session(10, vec![doc]).unwrap();
        f.index.commit().unwrap();
        let search = |scope: &Scope| {
            event_seqs(
                &f.index,
                &EventQuery {
                    q: "draft".into(),
                    ..Default::default()
                },
                scope,
            )
        };
        assert_eq!(
            search(&Scope {
                signed_in: true,
                viewer_id: Some(3),
                ..Default::default()
            }),
            Vec::<(i64, i64)>::new(),
            "a non-member cannot find an unpublished public event"
        );
        let mut published = event(11, 2, 9, "public", "public notes");
        published.published = true;
        f.index.replace_session(11, vec![published]).unwrap();
        f.index.commit().unwrap();
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    q: "public".into(),
                    ..Default::default()
                },
                &Scope::default()
            ),
            vec![(11, 2)],
            "a published event on a public repository is open to everyone"
        );
        assert_eq!(
            search(&Scope {
                member: vec![9],
                viewer_id: Some(3),
                ..Default::default()
            }),
            vec![(10, 1)],
            "a member can find the unpublished event"
        );
    }

    #[test]
    fn quarantined_events_need_upload_or_admin() {
        let f = fixture();
        let mut doc = event(10, 1, 9, "public", "flagged notes");
        doc.published = true;
        doc.quarantined = true;
        doc.uploader_id = 7;
        f.index.replace_session(10, vec![doc]).unwrap();
        f.index.commit().unwrap();
        let search = |scope: &Scope| {
            event_seqs(
                &f.index,
                &EventQuery {
                    q: "flagged".into(),
                    ..Default::default()
                },
                scope,
            )
        };
        assert_eq!(
            search(&Scope {
                signed_in: true,
                viewer_id: Some(3),
                ..Default::default()
            }),
            Vec::<(i64, i64)>::new(),
            "a stranger cannot find a quarantined event"
        );
        assert_eq!(
            search(&Scope {
                viewer_id: Some(7),
                ..Default::default()
            }),
            vec![(10, 1)],
            "the uploader can find their own quarantined event"
        );
        assert_eq!(
            search(&Scope {
                admin: vec![9],
                viewer_id: Some(3),
                ..Default::default()
            }),
            vec![(10, 1)],
            "a repo admin can find quarantined events"
        );
    }

    #[test]
    fn replace_trail_replaces_the_document() {
        let f = fixture();
        f.index
            .replace_trail(trail(1, 1, "public", "old title", "old body"))
            .unwrap();
        f.index.commit().unwrap();
        f.index
            .replace_trail(trail(1, 1, "public", "new title", "new body"))
            .unwrap();
        f.index.commit().unwrap();
        let scope = Scope::default();
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    q: "old".into(),
                    ..Default::default()
                },
                &scope
            ),
            Vec::<i64>::new()
        );
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    q: "new".into(),
                    ..Default::default()
                },
                &scope
            ),
            vec![1]
        );
        assert_eq!(
            f.index.stats().unwrap(),
            IndexStats {
                trails: 1,
                events: 0
            }
        );
    }

    #[test]
    fn drop_session_and_drop_repo_remove_documents() {
        let f = fixture();
        f.index
            .replace_trail(trail(1, 1, "public", "gone soon", "body"))
            .unwrap();
        f.index
            .replace_trail(trail(2, 2, "public", "stays", "body"))
            .unwrap();
        f.index
            .replace_session(10, vec![event(10, 1, 1, "public", "gone event")])
            .unwrap();
        f.index
            .replace_session(11, vec![event(11, 1, 2, "public", "stays event")])
            .unwrap();
        f.index.commit().unwrap();
        f.index.drop_session(10).unwrap();
        f.index.drop_repo(2).unwrap();
        f.index.commit().unwrap();
        let scope = wide();
        assert_eq!(
            f.index.stats().unwrap(),
            IndexStats {
                trails: 1,
                events: 0
            }
        );
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    q: "gone".into(),
                    ..Default::default()
                },
                &scope
            ),
            Vec::<(i64, i64)>::new()
        );
        assert_eq!(
            event_seqs(
                &f.index,
                &EventQuery {
                    q: "stays".into(),
                    ..Default::default()
                },
                &scope
            ),
            Vec::<(i64, i64)>::new(),
            "drop_repo removed the repository's events too"
        );
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    q: "stays".into(),
                    ..Default::default()
                },
                &scope
            ),
            Vec::<i64>::new(),
            "drop_repo removed the repository's Trail too"
        );
        assert_eq!(
            trail_ids(
                &f.index,
                &TrailQuery {
                    q: "gone".into(),
                    ..Default::default()
                },
                &scope
            ),
            vec![1],
            "the other repository's Trail stays"
        );
    }

    #[test]
    fn clear_removes_every_document() {
        let f = fixture();
        f.index
            .replace_trail(trail(1, 1, "public", "gone soon", "body"))
            .unwrap();
        f.index
            .replace_session(10, vec![event(10, 1, 1, "public", "gone event")])
            .unwrap();
        f.index.commit().unwrap();
        f.index.clear().unwrap();
        f.index.commit().unwrap();
        assert_eq!(
            f.index.stats().unwrap(),
            IndexStats {
                trails: 0,
                events: 0
            }
        );
    }

    #[test]
    fn search_is_newest_first_and_paginates() {
        let f = fixture();
        for (id, ts) in [(1, 100), (2, 300), (3, 200)] {
            let mut doc = trail(id, 1, "public", "shared", "body");
            doc.ts = ts;
            f.index.replace_trail(doc).unwrap();
        }
        f.index.commit().unwrap();
        let q = TrailQuery {
            q: "shared".into(),
            ..Default::default()
        };
        let page = |offset: usize, limit: usize| {
            f.index
                .search_trails(&q, &Scope::default(), offset, limit)
                .unwrap()
                .into_iter()
                .map(|hit| hit.trail_id)
                .collect::<Vec<_>>()
        };
        assert_eq!(page(0, 20), vec![2, 3, 1], "newest first");
        assert_eq!(page(1, 1), vec![3], "offset and limit");
        assert_eq!(page(3, 20), Vec::<i64>::new());
    }

    #[test]
    fn corrupt_or_missing_directories_recreate_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("garbage"), b"not an index").unwrap();
        let index = SearchIndex::open_or_create(dir.path()).unwrap();
        assert_eq!(
            index.stats().unwrap(),
            IndexStats {
                trails: 0,
                events: 0
            }
        );
        index
            .replace_trail(trail(1, 1, "public", "fresh", "body"))
            .unwrap();
        index.commit().unwrap();
        drop(index);
        // A fresh open finds what was committed. (A second writer in the same
        // process must not recreate the directory; the cross-process writer
        // lock is exercised by the `starforged index rebuild` test.)
        let reopened = SearchIndex::open_or_create(dir.path()).unwrap();
        assert_eq!(
            reopened.stats().unwrap(),
            IndexStats {
                trails: 1,
                events: 0
            }
        );
    }
}
