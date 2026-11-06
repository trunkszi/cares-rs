//! Dense poll indices, with the first 64 registrations in one bitmap word.
use uarch::prelude::*;
pub(super) struct ActiveSlots {
    chunks: Vec<Bitmap64>,
    count: usize,
}
impl ActiveSlots {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            chunks: vec![Bitmap64::new(0); capacity.div_ceil(64)],
            count: 0,
        }
    }
    #[inline]
    pub(super) fn insert(&mut self, slot: usize) {
        let chunk = slot >> 6;
        if chunk >= self.chunks.len() {
            self.chunks.resize(chunk + 1, Bitmap64::new(0));
        }
        let word = &mut self.chunks[chunk];
        let bit = (slot & 63) as u32;
        if !word.test(bit) {
            *word = word.set(bit);
            self.count += 1;
        }
    }
    #[inline]
    pub(super) fn remove(&mut self, slot: usize) {
        if let Some(word) = self.chunks.get_mut(slot >> 6) {
            let bit = (slot & 63) as u32;
            if word.test(bit) {
                *word = word.clear(bit);
                self.count -= 1;
            }
        }
    }
    #[inline]
    pub(super) fn next(&self, slot: usize) -> Option<usize> {
        let chunk = slot >> 6;
        let first = self.chunks.get(chunk)?.next_one_from((slot & 63) as u32);
        if let Some(bit) = first {
            return Some((chunk << 6) + bit as usize);
        }
        self.chunks
            .iter()
            .enumerate()
            .skip(chunk + 1)
            .find_map(|(index, word)| {
                word.lowest_one_index()
                    .map(|bit| (index << 6) + bit as usize)
            })
    }
    #[inline]
    pub(super) fn indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.chunks
            .iter()
            .enumerate()
            .flat_map(|(index, word)| word.iter_ones().map(move |bit| (index << 6) + bit as usize))
    }
    #[hot_inline]
    pub(super) fn len(&self) -> usize {
        self.count
    }
    pub(super) fn rebuild(&mut self, occupied: impl Iterator<Item = bool>) {
        self.chunks.fill(Bitmap64::new(0));
        self.count = 0;
        for (index, active) in occupied.enumerate() {
            if active {
                self.insert(index);
            }
        }
    }
    #[inline]
    pub(super) fn swap_remove(&mut self, slot: usize, last: usize) {
        let moved = self
            .chunks
            .get(last >> 6)
            .is_some_and(|word| word.test((last & 63) as u32));
        self.remove(last);
        self.remove(slot);
        if moved && slot != last {
            self.insert(slot);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_occupancy_spans_bitmap_chunks_and_survives_swap_removal() {
        let mut slots = ActiveSlots::new(1);
        for index in [0, 3, 63, 64, 65, 129] {
            slots.insert(index);
            slots.insert(index);
        }
        assert_eq!(slots.len(), 6);
        assert_eq!(slots.indices().collect::<Vec<_>>(), [0, 3, 63, 64, 65, 129]);
        assert_eq!(slots.next(4), Some(63));
        assert_eq!(slots.next(66), Some(129));
        assert_eq!(slots.next(130), None);
        slots.remove(3);
        slots.swap_remove(3, 129);
        assert_eq!(slots.indices().collect::<Vec<_>>(), [0, 3, 63, 64, 65]);
        assert_eq!(slots.len(), 5);
        slots.rebuild([false, true, false, true].into_iter());
        assert_eq!(slots.indices().collect::<Vec<_>>(), [1, 3]);
        assert_eq!(slots.len(), 2);
    }
    #[test]
    fn bitmap_boundaries_full_empty_and_rebuild_match_dense_model() {
        let mut slots = ActiveSlots::new(0);
        assert_eq!(slots.next(0), None);
        assert_eq!(slots.next(usize::MAX), None);
        slots.remove(usize::MAX);
        for index in (0..193).rev() {
            slots.insert(index);
            slots.insert(index);
        }
        assert_eq!(slots.len(), 193);
        for start in 0..193 {
            assert_eq!(slots.next(start), Some(start));
        }
        assert_eq!(slots.next(193), None);
        for index in (0..193).step_by(2) {
            slots.remove(index);
            slots.remove(index);
        }
        let expected: Vec<_> = (0..193).filter(|index| index % 2 != 0).collect();
        assert_eq!(slots.indices().collect::<Vec<_>>(), expected);
        assert_eq!(slots.len(), expected.len());
        for start in 0..=193 {
            assert_eq!(
                slots.next(start),
                expected.iter().copied().find(|&index| index >= start)
            );
        }
        slots.rebuild(std::iter::empty());
        assert_eq!(slots.len(), 0);
        assert_eq!(slots.next(0), None);
        slots.insert(63);
        slots.insert(64);
        slots.swap_remove(63, 64);
        assert_eq!(slots.indices().collect::<Vec<_>>(), [63]);
        slots.swap_remove(63, 63);
        assert_eq!(slots.len(), 0);
    }
}
