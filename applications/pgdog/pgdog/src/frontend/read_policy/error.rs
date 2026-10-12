use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyErrorKind {
    Syntax,
    Write,
    Unsupported,
    Protocol,
    Manifest,
    Io,
    Configuration,
    StatementName,
    PortalName,
    DuplicateStatement,
    DuplicatePortal,
}

/// Safe-to-report policy failure. Details deliberately contain reason codes only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyError {
    kind: PolicyErrorKind,
    reason: &'static str,
}

impl PolicyError {
    pub(crate) const fn new(kind: PolicyErrorKind, reason: &'static str) -> Self {
        Self { kind, reason }
    }

    pub(crate) const fn syntax() -> Self {
        Self::new(PolicyErrorKind::Syntax, "syntax_error")
    }

    pub(crate) const fn write() -> Self {
        Self::new(PolicyErrorKind::Write, "write_statement")
    }

    pub(crate) const fn unsupported() -> Self {
        Self::new(PolicyErrorKind::Unsupported, "unsupported_statement")
    }

    pub(crate) const fn protocol() -> Self {
        Self::new(PolicyErrorKind::Protocol, "unsupported_protocol_message")
    }

    pub(crate) const fn manifest(reason: &'static str) -> Self {
        Self::new(PolicyErrorKind::Manifest, reason)
    }

    pub(crate) const fn io() -> Self {
        Self::new(PolicyErrorKind::Io, "manifest_read_failed")
    }

    pub(crate) const fn configuration(reason: &'static str) -> Self {
        Self::new(PolicyErrorKind::Configuration, reason)
    }

    pub(crate) const fn statement_not_found() -> Self {
        Self::new(
            PolicyErrorKind::StatementName,
            "prepared_statement_not_found",
        )
    }

    pub(crate) const fn duplicate_statement() -> Self {
        Self::new(
            PolicyErrorKind::DuplicateStatement,
            "duplicate_prepared_statement",
        )
    }

    pub(crate) const fn stale_statement() -> Self {
        Self::new(PolicyErrorKind::StatementName, "stale_prepared_statement")
    }

    pub(crate) const fn portal_not_found() -> Self {
        Self::new(PolicyErrorKind::PortalName, "portal_not_found")
    }

    pub(crate) const fn duplicate_portal() -> Self {
        Self::new(PolicyErrorKind::DuplicatePortal, "duplicate_portal")
    }

    pub(crate) const fn stale_portal() -> Self {
        Self::new(PolicyErrorKind::PortalName, "stale_portal")
    }

    pub(crate) const fn reason(&self) -> &'static str {
        self.reason
    }

    pub(crate) const fn sqlstate(&self) -> &'static str {
        match self.kind {
            PolicyErrorKind::Write => "25006",
            PolicyErrorKind::Unsupported => "0A000",
            PolicyErrorKind::Syntax => "42601",
            PolicyErrorKind::Protocol => "08P01",
            PolicyErrorKind::StatementName => "26000",
            PolicyErrorKind::PortalName => "34000",
            PolicyErrorKind::DuplicateStatement => "42P05",
            PolicyErrorKind::DuplicatePortal => "42P03",
            PolicyErrorKind::Manifest | PolicyErrorKind::Io | PolicyErrorKind::Configuration => {
                "22023"
            }
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for PolicyError {}
