use super::*;

#[test]
fn exhausted_generation_rejects_stale_query() -> Result<()> {
    let state = Rc::new(CallbackState::new());
    let slot = || {
        let callback: QueryFn = Box::new(|_, _| {});
        CallbackSlot::new(Rc::clone(&state), callback)
    };
    let mut table = CallbackTable::default();
    let first = slot();
    let stale = table.insert(SlotKind::Query(Rc::clone(&first)), None, 1)?;
    let entry = table.entries[stale.index as usize]
        .as_mut()
        .ok_or_else(|| AresError::invalid_input("missing query"))?;
    entry.generation = u32::MAX;
    first.mark_completed();
    table.sweep();
    let next = slot();
    table.insert(SlotKind::Query(Rc::clone(&next)), None, 1)?;
    next.mark_completed();
    table.sweep();
    let current = table.insert(SlotKind::Query(slot()), None, 1)?;
    assert!(
        !table.take_slot(stale),
        "stale query must not cancel a new callback"
    );
    assert!(table.get(current).is_some());
    assert_ne!(current.index, stale.index);
    Ok(())
}
