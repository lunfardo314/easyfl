# Chess move validator — EasyFL local-script test scenario

## Purpose

Stress-test the local-script feature with a non-trivial real-world covenant:
validate a single chess move against the rules of chess, expressed entirely
as an EasyFL local script (no Go-level chess knowledge). The script is
compiled once via `Library[T].CompileLocalScript`, decoded into
`*LocalScript[T]`, and invoked from Go test cases that exercise legal moves,
illegal moves, and the starting-position predicate.

This is a test, not a production engine. Several rules are out of scope (see
[§6](#6-out-of-scope-v1-simplifications)); the goal is to exercise the
local-script feature end to end with realistic intra-script call patterns,
not to build a chess engine.

## 1. Board encoding (64 bytes)

The board state is a 64-byte array. Each byte encodes a single square:

| Bits | Field | Values |
| --- | --- | --- |
| 7..4 | color | `0x00` empty, `0x10` white, `0x20` black |
| 3..0 | piece | `0x0` none, `0x1` pawn, `0x2` knight, `0x3` bishop, `0x4` rook, `0x5` queen, `0x6` king |

Square index: `i = rank*8 + file`

- rank 0 = white's back rank (a1..h1, indices 0..7)
- rank 7 = black's back rank (a8..h8, indices 56..63)
- file 0 = a-file, file 7 = h-file

Helpful constants (matching the Go side):

```
EMPTY = 0x00
WHITE = 0x10, BLACK = 0x20
PAWN  = 0x01, KNIGHT = 0x02, BISHOP = 0x03,
ROOK  = 0x04, QUEEN  = 0x05, KING   = 0x06

WP = 0x11 (white pawn), WK = 0x16 (white king), WQ = 0x15, ...
BP = 0x21, BK = 0x26, ...
```

Standard starting position:

```
rank 0 (white back):  R N B Q K B N R
rank 1 (white pawns): P P P P P P P P
ranks 2..5:           empty
rank 6 (black pawns): p p p p p p p p
rank 7 (black back):  r n b q k b n r
```

## 2. Move encoding (5 bytes)

A move is a 5-byte tuple:

| Byte | Field | Notes |
| --- | --- | --- |
| 0 | from | 0..63 |
| 1 | to | 0..63 |
| 2 | piece | full byte: `color\|type` — same encoding as the board |
| 3 | flags | bit 0 (`0x01`) capture (validated against target square); bit 1 (`0x02`) check (recorded; **not** verified); bit 2 (`0x04`) checkmate (recorded; **not** verified) |
| 4 | reserved | must be `0x00` |

The check / checkmate flags are accepted as-is and not validated — verifying
them would require a full move-generation engine. They are kept in the spec
to mirror SAN/PGN conventions.

## 3. Functions exposed by the local script

The script exports two top-level functions; tests invoke them via wire indices
(toposort places no-deps fns first; `CompileLocalScriptWithIndex` returns the
source-symbol → wire-index mapping).

### `isStart(board)`

Returns truthy iff `board` byte-equals the canonical 64-byte starting
position. Implementation: a single `equal(board, 0x<64 hex bytes>)`.

### `move(startBoard, moveSpec, resultBoard)`

Returns truthy iff the move described by `moveSpec` is legal in `startBoard`
**and** applying it produces `resultBoard`. Specifically:

#### (a) Wire-format checks
- `len(startBoard) == 64`
- `len(resultBoard) == 64`
- `len(moveSpec) == 5`
- `moveSpec[0]` (from) and `moveSpec[1]` (to) are both in 0..63
- `moveSpec[4]` is `0x00`
- `flags` only has valid bits set (lower 3 bits)

#### (b) Source square sanity
- `byte(startBoard, from) == moveSpec[2]` (declared piece is there)

#### (c) Target square sanity
- if capture flag set: `byte(startBoard, to)` is non-empty **and** of the
  opposite color from the moving piece
- if capture flag not set: `byte(startBoard, to) == EMPTY`

#### (d) Move geometry — depends on piece type

- **Pawn:** 1 step forward to empty square; or 2 steps forward from starting
  rank (rank 1 for white, rank 6 for black) with **both** the intermediate
  and target empty; or 1 step diagonal forward capturing an opposing piece
  (capture flag must be set).
- **Knight:** one of 8 L-shaped offsets, target square handled in (c).
- **Bishop:** diagonal, all intermediate squares empty.
- **Rook:** orthogonal (rank or file), all intermediates empty.
- **Queen:** bishop-like or rook-like.
- **King:** one square in any of 8 directions.

#### (e) Resulting board
- For every square `s != from`, `s != to`: `byte(resultBoard, s) == byte(startBoard, s)`.
- `byte(resultBoard, from) == EMPTY`
- `byte(resultBoard, to) == moveSpec[2]` (the moving piece)

## 4. Path-clear (no-obstacle) check

For sliding pieces (bishop, rook, queen) the longest single-move path is 7
squares (e.g. a1 → h8), giving up to 6 intermediate squares to check. The
script provides one helper:

### `pathClear(board, from, direction, count)`

Returns truthy iff for every `k` in `1..count` the square at (`from` offset
by `k` steps in `direction`) is `EMPTY`. `count` is the number of
intermediate squares to inspect — i.e., for a move of distance `N` (in
single-square steps), `count = N - 1`.

Implementation: a single `pathClear` function dispatches on `direction` (8
cases) to a direction-specific kernel that performs 6 unrolled checks, each
of the form `or(lessThan(count, K), isZero(byte(board, sq)))` where `sq` is
computed by `add` (or `sub` for "negative" directions) of `K` from `from`.
The 6-step unroll covers the maximum chess move.

Direction encoding (1-byte enum):

| Value | Direction | Step |
| --- | --- | --- |
| 0 | E | file++, +1 |
| 1 | W | file--, -1 |
| 2 | N | rank++, +8 |
| 3 | S | rank--, -8 |
| 4 | NE | rank++ file++, +9 |
| 5 | SW | rank-- file--, -9 |
| 6 | NW | rank++ file--, +7 |
| 7 | SE | rank-- file++, -7 |

The reason for an enum rather than a signed byte step is that EasyFL
arithmetic is unsigned uint64; encoding a "negative step" as a two's-
complement byte is awkward to handle uniformly. With an enum, each direction
kernel uses the appropriate `add`/`sub` to advance, and signed arithmetic
stays out of the source.

Geometry helpers (e.g. `isBishopMove`) determine the direction enum from the
signs of (rank diff, file diff), determine count from `|rank diff| - 1`,
then call `pathClear` once.

## 5. Internal helper functions (intra-script calls)

Beyond the two exported entry points, the script defines the following
helpers. Each is a separate local-script function; they call each other via
the 3-byte intra-script call prefix. This is the main thing being stressed.

### Leaf helpers
- `colorOf(piece)` — `piece & 0xf0`
- `typeOf(piece)` — `piece & 0x0f`
- `oppColor(a, b)` — both non-empty and different colors
- `rankOf(sq)` — `sq / 8`
- `fileOf(sq)` — `sq % 8`
- `absDiff(a, b)` — `|a-b|`, computed without conditionals using `lessThan` + `sub`
- `isNorth(from, to)`, `isEast(from, to)` — direction comparators
- `sq1(x)` — take LSB of an 8-byte arithmetic result

### Path-clear
- `pclE`, `pclW`, `pclN`, `pclS`, `pclNE`, `pclSW`, `pclNW`, `pclSE` — direction kernels
- `pathClear` — dispatcher

### Per-piece geometry
- `isPawnMove(board, from, to, flags, piece)` — pawn dispatch on color (`isWPM` for white, `isBPM` for black)
- `isKnightMove(from, to)`
- `isBishopMove(board, from, to)`
- `isRookMove(board, from, to)`
- `isQueenMove(board, from, to)` — `isBishopMove` ∨ `isRookMove`
- `isKingMove(from, to)`
- `geometryOK(board, from, to, flags, piece)` — `selectCaseByIndex(typeOf(piece), …)`

### Source/target/wire/result
- `sourceOK(board, from, piece)`
- `targetOK(board, to, piece, flags)`
- `wireOK(start, spec, result)`
- `expAt(start, from, to, piece, idx)` — expected byte at `idx` in result
- `chunkRes(start, result, from, to, piece, baseIdx)` — equality of 8 consecutive squares
- `resOK(start, result, from, to, piece)` — 64-square equality via 8 chunks (works around the 15-arg cap on `and`)

## 6. Out of scope (v1 simplifications)

- **Castling.** Requires tracking castling rights — extra state outside the board. Returning to it would require changing the move encoding.
- **En passant.** Requires "last move" state.
- **Pawn promotion.** Requires extending the move encoding with a promotion-piece byte.
- **Whose turn it is** (color alternation). The validator has no concept of "current player": it accepts any individually-legal move regardless of alternation. A higher layer (or a follow-up pass) would track turns.
- **"Don't leave own king in check."** Requires a full attack-square test against the resulting position; non-trivial without loops. The check / checkmate flags in `moveSpec` are recorded but not verified.
- 50-move rule, threefold repetition, insufficient material, stalemate.
- Move legality across the entire game (validator is per-move).

All of the above are explicitly noted so a caller knows what they get.

## 7. Test cases

Compile-once-eval-many: the local script is compiled and decoded once per
test (or once via testing helpers and reused).

### Starting position
- `isStart` on the canonical start position → true
- `isStart` on the start position with one square modified → false
- `isStart` on a board with wrong length → false

### Pawn moves
- 1-square forward from rank 1 (white) → true
- 2-square forward from rank 1 (white) → true
- 2-square forward from rank 2 (white) → false (not starting rank)
- 2-square forward blocked by piece on rank 2 → false
- 1-square forward to occupied square → false
- Diagonal capture of opposite-color piece → true
- Diagonal capture of same-color piece → false
- Diagonal move with no piece to capture → false
- Same flow mirrored for black pawn

### Knight moves
- All 8 L-shapes from a central square → true
- Move that lands on same-color piece → false
- Move that lands on opposite-color piece with capture flag → true

### Bishop / Rook / Queen
- Clear diagonal/file/rank → true
- Blocked path → false
- Queen exhibits both bishop-like and rook-like moves

### King
- All 8 adjacent squares → true
- 2-square move → false (also covers the castling-not-supported negative case)

### Resulting-board consistency
- Correct apply → true
- One unrelated square changed → false
- From-square not cleared → false
- To-square has wrong piece → false

### Wire-format negatives
- Wrong board length → false
- Wrong moveSpec length → false
- `moveSpec[4] != 0` → false
- `flags` has high bits set → false

### Sample game (smoke)
- 1. e4 e5 2. Nf3 Nc6 3. Bb5 a6 — three moves per side, validated in
  sequence; each move produces the next start board for the next test step.

## 8. Implementation plan

1. Generate the canonical 64-byte starting position as a hex literal embedded
   in the local-script source for `isStart`.
2. Write the helper fns (`colorOf`, `typeOf`, ranks, files, `oppColor`, …) in
   EasyFL.
3. Write `isXxxMove` geometry checks, then `geometryOK` dispatch.
4. Write `pathClear` with 6 unrolled checks per direction.
5. Write `resOK`, `targetOK`, `sourceOK`, `wireOK`.
6. Tie it all together in `move()`.
7. Compile via `Library[T].CompileLocalScriptWithIndex` so tests can invoke
   functions by source-level name.
