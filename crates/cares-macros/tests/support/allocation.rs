//! Count allocations on the current test thread only.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

thread_local! {
    static COUNT: Cell<Option<usize>> = const { Cell::new(None) };
}

struct TrackingAllocator;

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn allocated() {
    let _result = COUNT.try_with(|count| {
        if let Some(value) = count.get() {
            count.set(Some(value + 1));
        }
    });
}

// SAFETY: every allocation and deallocation is forwarded unchanged to System.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocated();
        // SAFETY: the caller provides the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocated();
        // SAFETY: the caller provides the layout required by GlobalAlloc.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocated();
        // SAFETY: the pointer, original layout and new size come from GlobalAlloc's caller.
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the pointer was allocated by System with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

pub fn start() {
    COUNT.with(|count| count.set(Some(0)));
}
pub fn finish() -> usize {
    COUNT.with(|count| count.replace(None).unwrap_or(0))
}
