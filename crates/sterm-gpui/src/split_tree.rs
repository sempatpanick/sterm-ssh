//! Arbitrary nested horizontal/vertical split-pane layout tree.
//!
//! Typed pure-Rust integration of `src/lib/split-tree.ts` (behavior-verified in `rust/lib-rs`).

#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitDirection {
    Horizontal,
    Vertical,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SplitNode {
    Leaf {
        pane_id: String,
    },
    Split {
        id: String,
        direction: SplitDirection,
        /// Clamped to `0.15..=0.85`.
        ratio: f32,
        first: Box<SplitNode>,
        second: Box<SplitNode>,
    },
}

pub fn create_leaf(pane_id: impl Into<String>) -> SplitNode {
    SplitNode::Leaf {
        pane_id: pane_id.into(),
    }
}

pub fn split_pane(
    root: SplitNode,
    target_pane_id: &str,
    new_pane_id: &str,
    direction: SplitDirection,
    split_id: &str,
) -> SplitNode {
    match root {
        SplitNode::Leaf { pane_id } => {
            if pane_id != target_pane_id {
                return SplitNode::Leaf { pane_id };
            }
            SplitNode::Split {
                id: split_id.to_string(),
                direction,
                ratio: 0.5,
                first: Box::new(SplitNode::Leaf { pane_id }),
                second: Box::new(create_leaf(new_pane_id)),
            }
        }
        SplitNode::Split {
            id,
            direction: dir,
            ratio,
            first,
            second,
        } => SplitNode::Split {
            id,
            direction: dir,
            ratio,
            first: Box::new(split_pane(
                *first,
                target_pane_id,
                new_pane_id,
                direction,
                split_id,
            )),
            second: Box::new(split_pane(
                *second,
                target_pane_id,
                new_pane_id,
                direction,
                split_id,
            )),
        },
    }
}

pub fn close_pane(root: SplitNode, target_pane_id: &str) -> Option<SplitNode> {
    match root {
        SplitNode::Leaf { pane_id } => {
            if pane_id == target_pane_id {
                None
            } else {
                Some(SplitNode::Leaf { pane_id })
            }
        }
        SplitNode::Split {
            id,
            direction,
            ratio,
            first,
            second,
        } => {
            let next_first = close_pane(*first, target_pane_id);
            let next_second = close_pane(*second, target_pane_id);
            match (next_first, next_second) {
                (None, None) => None,
                (None, Some(s)) => Some(s),
                (Some(f), None) => Some(f),
                (Some(f), Some(s)) => Some(SplitNode::Split {
                    id,
                    direction,
                    ratio,
                    first: Box::new(f),
                    second: Box::new(s),
                }),
            }
        }
    }
}

pub fn update_split_ratio(root: SplitNode, split_id: &str, ratio: f32) -> SplitNode {
    let clamped = if ratio.is_nan() {
        0.5
    } else {
        ratio.clamp(0.15, 0.85)
    };
    match root {
        leaf @ SplitNode::Leaf { .. } => leaf,
        SplitNode::Split {
            id,
            direction,
            ratio: current,
            first,
            second,
        } => {
            if id == split_id {
                SplitNode::Split {
                    id,
                    direction,
                    ratio: clamped,
                    first,
                    second,
                }
            } else {
                SplitNode::Split {
                    id,
                    direction,
                    ratio: current,
                    first: Box::new(update_split_ratio(*first, split_id, clamped)),
                    second: Box::new(update_split_ratio(*second, split_id, clamped)),
                }
            }
        }
    }
}

pub fn collect_pane_ids(root: &SplitNode) -> Vec<String> {
    let mut out = Vec::new();
    collect_into(root, &mut out);
    out
}

fn collect_into(node: &SplitNode, out: &mut Vec<String>) {
    match node {
        SplitNode::Leaf { pane_id } => out.push(pane_id.clone()),
        SplitNode::Split { first, second, .. } => {
            collect_into(first, out);
            collect_into(second, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_resizes_and_promotes_sibling_on_close() {
        let root = create_leaf("p1");
        let s1 = split_pane(root, "p1", "p2", SplitDirection::Horizontal, "sp1");
        let s2 = split_pane(s1, "p2", "p3", SplitDirection::Vertical, "sp2");

        assert_eq!(collect_pane_ids(&s2), vec!["p1", "p2", "p3"]);

        let resized = update_split_ratio(s2, "sp1", 0.99);
        match &resized {
            SplitNode::Split { ratio, .. } => assert!((*ratio - 0.85).abs() < 1e-6),
            SplitNode::Leaf { .. } => panic!("expected split node"),
        }

        let after_p2 = close_pane(resized, "p2").expect("p1 & p3 remain");
        assert_eq!(collect_pane_ids(&after_p2), vec!["p1", "p3"]);

        let after_p1 = close_pane(after_p2, "p1").expect("p3 remains");
        assert_eq!(after_p1, create_leaf("p3"));
        assert!(close_pane(after_p1, "p3").is_none());
    }
}
