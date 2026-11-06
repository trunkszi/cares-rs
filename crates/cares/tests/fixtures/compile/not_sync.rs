fn require_sync<T: Sync>() {}
pub fn reject() { require_sync::<cares::Resolver>(); }
