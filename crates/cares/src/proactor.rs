//! Shared-ring driver that routes `liburing` socket and timer completions into
//! a [`Resolver`].

use std::{cell::RefCell, collections::VecDeque, os::fd::RawFd, rc::Rc, time::Instant};

use liburing::{
    Proactor, SubmissionContext, UringError,
    id::{OpId, OpPayload, SubsystemId},
    ops::timeout::Timeout,
    socket_bridge::{
        BridgeError, BridgeSubmission, SocketInterest as UringInterest, UringSocketBridge,
        UringSocketOps,
    },
};

use crate::{
    error::{AresError, Result},
    options::ResolverOptions,
    resolver::{Resolver, ResolverCqe},
    socket_bridge::{ReadinessSink, SocketInterest},
};

pub(crate) type Queue = Rc<RefCell<VecDeque<(OpId, BridgeSubmission<OpId>)>>>;

pub(crate) struct Ops {
    pub(crate) id: SubsystemId,
    pub(crate) queue: Queue,
}

impl UringSocketOps for Ops {
    type OpId = OpId;
    type Error = UringError;

    fn subsystem_id(&self) -> SubsystemId {
        self.id
    }

    fn submit(&mut self, token: u64, submission: BridgeSubmission<OpId>) -> liburing::Result<OpId> {
        let id = OpId::pack(
            self.id,
            OpPayload::new(token).ok_or(UringError::PayloadOverflow(token))?,
        );
        self.queue.borrow_mut().push_back((id, submission));
        Ok(id)
    }
}

pub(crate) struct Sink {
    pub(crate) bridge: Rc<RefCell<UringSocketBridge<Ops>>>,
}

impl ReadinessSink for Sink {
    fn update_interest(&self, fd: i32, interest: SocketInterest) {
        let mut bridge = self.bridge.borrow_mut();
        let registered = bridge.register(fd as RawFd).or_else(|error| match error {
            BridgeError::AlreadyRegistered => Ok(()),
            other => Err(other),
        });
        if registered.is_ok() {
            let mut mask = UringInterest::EMPTY;
            if interest.readable {
                mask |= UringInterest::READABLE;
            }
            if interest.writable {
                mask |= UringInterest::WRITABLE;
            }
            drop(bridge.set_interest(fd as RawFd, mask));
        }
    }

    fn remove_interest(&self, fd: i32) {
        let mut bridge = self.bridge.borrow_mut();
        drop(bridge.set_interest(fd as RawFd, UringInterest::EMPTY));
    }
}

/// Drives one [`Resolver`] from a shared `liburing` ring.
///
/// The driver owns the socket bridge and every armed c-ares deadline. Drop it
/// only after `Proactor::shutdown` has drained its completions: the timeout
/// operands must outlive their final CQEs.
pub struct ProactorResolver {
    pub resolver: Resolver,
    pub(crate) bridge: Rc<RefCell<UringSocketBridge<Ops>>>,
    pub(crate) queue: Queue,
    subsystem: SubsystemId,
    timers: Vec<(u64, u64, Timeout)>,
    next_timer_token: u64,
    armed_generation: Option<u64>,
}

impl ProactorResolver {
    /// Creates a driver for one non-internal proactor subsystem.
    ///
    /// # Errors
    /// Returns a resolver, proactor, or socket-bridge construction error.
    pub fn new(
        subsystem: SubsystemId,
        options: ResolverOptions,
        servers_csv: &str,
        capacity: usize,
    ) -> Result<Self> {
        let queue: Queue = Rc::new(RefCell::new(VecDeque::new()));
        let bridge = UringSocketBridge::new(
            subsystem,
            Ops {
                id: subsystem,
                queue: Rc::clone(&queue),
            },
            capacity,
        )
        .map_err(|error| AresError::invalid_input(format!("socket bridge: {error}")))?;
        let bridge = Rc::new(RefCell::new(bridge));
        let mut resolver = Resolver::new(options)?;
        resolver.set_servers_csv(servers_csv)?;
        resolver.install_readiness_sink(Rc::new(Sink {
            bridge: Rc::clone(&bridge),
        }))?;
        Ok(Self {
            resolver,
            bridge,
            queue,
            subsystem,
            timers: Vec::new(),
            next_timer_token: OpPayload::MAX_RAW,
            armed_generation: None,
        })
    }

    /// Stages queued socket work and the next c-ares deadline.
    ///
    /// # Errors
    /// Returns a proactor submission or channel error.
    pub fn flush(&mut self, proactor: &mut Proactor) -> Result<()> {
        loop {
            let Some((id, submission)) = self.queue.borrow().front().copied() else {
                break;
            };
            proactor
                .prepare_sqe_with(id, |sqe| {
                    // SAFETY: The submission owns no DMA; the bridge owns the descriptor.
                    unsafe { crate::resolver::prepare_bridge_sqe(sqe, submission) }
                })
                .map_err(|error| AresError::invalid_input(format!("proactor: {error}")))?;
            self.queue.borrow_mut().pop_front();
        }
        self.arm_timer(|id, timeout| {
            proactor.prepare_sqe_with(id, |sqe| {
                // SAFETY: `timeout` is retained until its final CQE or shutdown.
                unsafe { timeout.prepare(sqe) }
            })
        })
        .map_err(|error| AresError::invalid_input(format!("timer: {error}")))
    }

    pub(crate) fn flush_into(
        &mut self,
        submissions: &mut SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        loop {
            let Some((id, submission)) = self.queue.borrow().front().copied() else {
                break;
            };
            match submissions.prepare_sqe_with(id, |sqe| {
                // SAFETY: The submission owns no DMA; the bridge owns the descriptor.
                unsafe { crate::resolver::prepare_bridge_sqe(sqe, submission) }
            }) {
                Ok(()) => drop(self.queue.borrow_mut().pop_front()),
                // Shutdown provides a zero-capacity context; keep it queued.
                Err(UringError::SqRingFull) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        self.arm_timer(|id, timeout| {
            submissions.prepare_sqe_with(id, |sqe| {
                // SAFETY: `timeout` is retained until its final CQE or shutdown.
                unsafe { timeout.prepare(sqe) }
            })
        })
    }

    /// Removes and returns the generation of a timer completion, if any.
    pub(crate) fn take_timer(&mut self, op_id: OpId) -> Option<u64> {
        let token = op_id.payload().raw();
        let index = self.timers.iter().position(|(value, ..)| *value == token)?;
        let (_, generation, timeout) = self.timers.remove(index);
        drop(timeout);
        Some(generation)
    }

    /// Arms the earliest c-ares deadline when it changed since the last arm.
    fn arm_timer<F>(&mut self, mut prepare: F) -> liburing::Result<()>
    where
        F: FnMut(OpId, &Timeout) -> liburing::Result<()>,
    {
        let Some(deadline) = self
            .resolver
            .timer_deadline()
            .map_err(|_| UringError::InvalidConfig("timer deadline failed"))?
        else {
            return Ok(());
        };
        if self.armed_generation == Some(deadline.generation) {
            return Ok(());
        }
        let delay = deadline.at.saturating_duration_since(Instant::now());
        let timeout = Timeout::new(delay)?;
        let token = self.next_timer_token;
        self.next_timer_token = if token > 1 {
            token - 1
        } else {
            OpPayload::MAX_RAW
        };
        let id = OpId::pack(
            self.subsystem,
            OpPayload::new(token).ok_or(UringError::PayloadOverflow(token))?,
        );
        match prepare(id, &timeout) {
            Ok(()) => {}
            // Backpressure: the deadline is re-armed by the next flush.
            Err(UringError::SqRingFull) => return Ok(()),
            Err(error) => return Err(error),
        }
        self.timers.push((token, deadline.generation, timeout));
        self.armed_generation = Some(deadline.generation);
        Ok(())
    }
}

impl liburing::SubsystemHandler for ProactorResolver {
    fn on_completion(
        &mut self,
        completion: liburing::Completion,
        submissions: &mut liburing::SubmissionContext<'_>,
    ) -> liburing::Result<()> {
        if let Some(generation) = self.take_timer(completion.op_id) {
            if self
                .resolver
                .on_cqe(ResolverCqe::Timer { generation })
                .is_err()
            {
                return Err(liburing::UringError::InvalidConfig(
                    "resolver timer completion failed",
                ));
            }
            return self.flush_into(submissions);
        }
        let event = self.bridge.borrow_mut().on_completion(completion);
        if let Some(event) = event
            && !event.interest.is_empty()
        {
            use liburing::socket_bridge::SocketInterest;
            let cqe = ResolverCqe::Socket {
                fd: event.fd,
                readable: event.interest.contains(SocketInterest::READABLE),
                writable: event.interest.contains(SocketInterest::WRITABLE),
            };
            if self.resolver.on_cqe(cqe).is_err() {
                return Err(liburing::UringError::InvalidConfig(
                    "resolver completion failed",
                ));
            }
        }
        self.bridge
            .borrow_mut()
            .drive()
            .map_err(|_| liburing::UringError::InvalidConfig("socket bridge drive failed"))?;
        self.flush_into(submissions)
    }
}
