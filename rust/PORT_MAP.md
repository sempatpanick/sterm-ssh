# Port map: sterm

2 of 10 units have a Rust port; no original changed since it was recorded.

## Ports

| Unit | Crate | In Rust | Kept in the original | Cases | Last diff | Original |
| --- | --- | --- | --- | ---: | ---: | --- |
| `src/lib/` | `rust/lib-rs` | `shouldRecordCommand`, `rankCommandSuggestions`, `computeInsertPayload`, `createLeaf`, `splitPane`, `closePane`, `updateSplitRatio`, `collectPaneIds` | - | 1918 | 1918/1918 | unchanged |
| `src/styles/` | `rust/styles-rs` | `getTerminalTheme`, `getTerminalFontStack` | - | 422 | 422/422 | unchanged |

## Not ported yet

In the order `analyze` suggests.

| Unit | Lines | Exports | Readiness |
| --- | ---: | ---: | ---: |
| `src/App.tsx` | 22 | 0 | 100 |
| `src/main.tsx` | 9 | 0 | 100 |
| `src/components/layout/` | 474 | 0 | 77 |
| `src/components/account/` | 474 | 0 | 72 |
| `src/components/sftp/` | 684 | 0 | 49 |
| `src/stores/` | 685 | 0 | 44 |
| `src/components/terminal/` | 1210 | 0 | 31 |
| `src/components/vault/` | 1921 | 0 | 25 |

Regenerate with `rust-anything map --write`. Commit this file: when the original changes upstream, the next map marks every port whose recording it outdated.
