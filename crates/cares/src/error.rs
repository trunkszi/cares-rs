//! c-ares status preservation and resolver error classification.

use std::ffi::CStr;

/// Whether repeating an operation can reasonably succeed without changing input.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorKind {
    /// A transport or remote-server failure that may succeed on a later attempt.
    Temporal,
    /// Invalid input, a definitive negative answer, or a local lifecycle failure.
    Fatal,
}

macro_rules! statuses {
    ($($variant:ident = $value:literal => $name:ident;)+) => {
        /// Every c-ares 1.34.9 status, preserving unrecognized integer values.
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub enum AresStatus {
            $(#[doc = stringify!($name)] $variant,)+
            /// An unrecognized status from the C library.
            Unknown(i32),
        }

        impl AresStatus {
            /// Converts a C status without discarding unknown values.
            ///
            /// # Panics
            /// This function does not panic.
            pub const fn from_raw(value: i32) -> Self {
                match value { $($value => Self::$variant,)+ value => Self::Unknown(value) }
            }

            /// Returns the original C status integer.
            ///
            /// # Panics
            /// This function does not panic.
            pub const fn as_raw(self) -> i32 {
                match self { $(Self::$variant => $value,)+ Self::Unknown(value) => value }
            }

            $(
                #[doc = concat!("The upstream `", stringify!($name), "` status.")]
                pub const $name: Self = Self::$variant;
            )+
        }
    };
}

statuses! {
    Success = 0 => ARES_SUCCESS;
    NoData = 1 => ARES_ENODATA;
    FormErr = 2 => ARES_EFORMERR;
    ServFail = 3 => ARES_ESERVFAIL;
    NotFound = 4 => ARES_ENOTFOUND;
    NotImplemented = 5 => ARES_ENOTIMP;
    Refused = 6 => ARES_EREFUSED;
    BadQuery = 7 => ARES_EBADQUERY;
    BadName = 8 => ARES_EBADNAME;
    BadFamily = 9 => ARES_EBADFAMILY;
    BadResponse = 10 => ARES_EBADRESP;
    ConnectionRefused = 11 => ARES_ECONNREFUSED;
    Timeout = 12 => ARES_ETIMEOUT;
    EndOfFile = 13 => ARES_EOF;
    File = 14 => ARES_EFILE;
    OutOfMemory = 15 => ARES_ENOMEM;
    Destruction = 16 => ARES_EDESTRUCTION;
    BadString = 17 => ARES_EBADSTR;
    BadFlags = 18 => ARES_EBADFLAGS;
    NoName = 19 => ARES_ENONAME;
    BadHints = 20 => ARES_EBADHINTS;
    NotInitialized = 21 => ARES_ENOTINITIALIZED;
    LoadIpHelper = 22 => ARES_ELOADIPHLPAPI;
    AddressGetNetworkParams = 23 => ARES_EADDRGETNETWORKPARAMS;
    Cancelled = 24 => ARES_ECANCELLED;
    Service = 25 => ARES_ESERVICE;
    NoServer = 26 => ARES_ENOSERVER;
}

impl AresStatus {
    /// The channel-destruction status.
    #[allow(non_upper_case_globals)]
    pub const Destroyed: Self = Self::Destruction;
    /// The remote server-failure status.
    #[allow(non_upper_case_globals)]
    pub const ServerFail: Self = Self::ServFail;
    /// The C library's out-of-memory status.
    #[allow(non_upper_case_globals)]
    pub const NoMem: Self = Self::OutOfMemory;

    /// Reports whether the operation completed successfully.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }

    /// Classifies failed operations; success has no error kind.
    ///
    /// Negative DNS answers are fatal for the current query. `Temporal` means a
    /// retry can help, rather than promising that the resolver will retry.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn kind(self) -> Option<ErrorKind> {
        match self {
            Self::Success => None,
            Self::ServFail
            | Self::Refused
            | Self::ConnectionRefused
            | Self::Timeout
            | Self::EndOfFile => Some(ErrorKind::Temporal),
            _ => Some(ErrorKind::Fatal),
        }
    }

    /// Copies the library's human-readable `ares_strerror` description.
    ///
    /// # Panics
    /// This function has no explicit panic path; allocation follows Rust's
    /// allocator failure policy.
    pub fn message(self) -> String {
        // SAFETY: ares_strerror accepts any integer, does not require library
        // initialization, and returns a static NUL-terminated string or null.
        let ptr = unsafe { cares_sys::ares_strerror(self.as_raw()) };
        if ptr.is_null() {
            return format!("unknown c-ares status {}", self.as_raw());
        }
        // SAFETY: the checked non-null pointer names the static NUL-terminated
        // description returned by ares_strerror; the owned copy cannot outlive it.
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

impl From<i32> for AresStatus {
    fn from(value: i32) -> Self {
        Self::from_raw(value)
    }
}

impl From<cares_sys::ares_status_t> for AresStatus {
    fn from(value: cares_sys::ares_status_t) -> Self {
        Self::from_raw(value.0 as i32)
    }
}

impl From<AresStatus> for i32 {
    fn from(value: AresStatus) -> Self {
        value.as_raw()
    }
}

/// Failures from the C library and the Rust safety boundary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AresError {
    /// A c-ares status and its upstream description.
    #[error("{message} (c-ares status {status:?})")]
    Status {
        /// Exact status, including unknown integer values.
        status: AresStatus,
        /// Owned `ares_strerror` description.
        message: String,
    },
    /// Input cannot be represented or accepted by the C interface.
    #[error("invalid resolver input: {0}")]
    InvalidInput(String),
    /// A DNS message is malformed or does not contain the requested field.
    #[error("invalid DNS record: {0}")]
    InvalidRecord(String),
    /// An allocation API returned null without a separate status.
    #[error("c-ares allocation failed")]
    AllocationFailed,
    /// Event-loop driving was attempted from a synchronous completion callback.
    #[error("driving the resolver from a completion callback is forbidden")]
    ReentrantDriveForbidden,
    /// The linked C library violates the threadless build contract.
    #[error("c-ares was compiled with thread safety enabled")]
    ThreadSafetyEnabled,
    /// A user callback panicked and poisoned its resolver.
    #[error("a resolver callback panicked")]
    CallbackPanicked,
}

impl AresError {
    /// Wraps an integer status with the C library's error description.
    ///
    /// Callers should use [`Self::check`] when success is possible.
    ///
    /// # Panics
    /// This function has no explicit panic path; allocation follows Rust's
    /// allocator failure policy.
    pub fn from_status(status: impl Into<AresStatus>) -> Self {
        let status = status.into();
        Self::Status {
            status,
            message: status.message(),
        }
    }

    /// Converts `ARES_SUCCESS` into success and every other status into an error.
    ///
    /// # Errors
    /// Returns the exact non-success status and its upstream description.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn check(status: impl Into<AresStatus>) -> Result<()> {
        let status = status.into();
        if status.is_success() {
            Ok(())
        } else {
            Err(Self::from_status(status))
        }
    }

    /// Creates an input validation error.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::InvalidInput(message.into())
    }

    /// Creates a malformed or missing record-field error.
    ///
    /// # Panics
    /// This function has no explicit panic path.
    pub fn invalid_record(message: impl Into<String>) -> Self {
        Self::InvalidRecord(message.into())
    }

    /// Returns the C status when this error originated in c-ares.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn status(&self) -> Option<AresStatus> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Classifies this error for retry decisions.
    ///
    /// # Panics
    /// This function does not panic.
    pub const fn kind(&self) -> ErrorKind {
        match self {
            Self::Status { status, .. } => match status.kind() {
                Some(kind) => kind,
                None => ErrorKind::Fatal,
            },
            _ => ErrorKind::Fatal,
        }
    }
}

impl From<std::ffi::NulError> for AresError {
    fn from(value: std::ffi::NulError) -> Self {
        Self::InvalidInput(value.to_string())
    }
}

impl From<AresStatus> for AresError {
    fn from(value: AresStatus) -> Self {
        Self::from_status(value)
    }
}

impl From<cares_sys::ares_status_t> for AresError {
    fn from(value: cares_sys::ares_status_t) -> Self {
        Self::from_status(value)
    }
}

/// Result type used throughout the safe resolver interface.
pub type Result<T> = std::result::Result<T, AresError>;
