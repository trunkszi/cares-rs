fn require_send<T: Send>() {}
pub fn reject() { require_send::<cares::Resolver>(); }
