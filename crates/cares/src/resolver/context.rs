//! Callback-scoped query submission and logical cancellation capabilities.

use uarch::prelude::cold_sink;

use super::*;

/// Restricted channel handle exposed to completion callbacks.
///
/// The handle permits follow-up submissions and per-query cancellation. It cannot
/// drive the event loop, reinitialize, or destroy the channel.
#[repr(transparent)]
pub struct ChannelCtx<'cb> {
    pub(crate) host: &'cb ResolverHost,
}

impl ChannelCtx<'_> {
    /// Submits a follow-up DNS query from inside a completion callback.
    ///
    /// # Errors
    /// Returns the same errors as [`Resolver::submit_query`].
    pub fn submit_query<F>(
        &self,
        name: &str,
        record_type: DnsRecordType,
        callback: F,
    ) -> Result<QueryHandle>
    where
        F: for<'cb> FnOnce(&ChannelCtx<'cb>, QueryOutcome<'cb>) + 'static,
    {
        submit_query_on(self.host, name, record_type, callback)
    }

    /// Sends a pre-built message from inside a completion callback.
    ///
    /// # Errors
    /// Returns the same errors as [`Resolver::submit_record`].
    pub fn submit_record<F>(&self, record: &DnsRecord, callback: F) -> Result<QueryHandle>
    where
        F: for<'cb> FnOnce(&ChannelCtx<'cb>, QueryOutcome<'cb>) + 'static,
    {
        let owned = record.try_clone()?;
        let raw = owned.as_ref().as_ptr();
        dispatch(
            self.host,
            query_slot(self.host, callback),
            Some(owned),
            Submission::Record { raw },
            reclaim::<QueryFn>,
        )
    }

    /// Cancels one query without disturbing the rest of the channel.
    ///
    /// # Errors
    /// Returns the same errors as [`Resolver::cancel_query`].
    pub fn cancel(&self, handle: QueryHandle) -> Result<()> {
        cancel_query_on(self.host, handle)
    }

    /// Reports whether a completion callback panicked.
    pub fn is_poisoned(&self) -> bool {
        self.host.is_poisoned()
    }
}

#[cold_sink]
pub(super) fn query_handle_error(message: &'static str) -> AresError {
    AresError::invalid_input(message)
}
uarch::layout::assert_layout!(ChannelCtx<'static>, size = 8, align = 8, fields = { host: 0 });
