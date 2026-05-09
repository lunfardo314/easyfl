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

## 1. Board encoding (67 bytes)

The board state is a 67-byte array: 64 square bytes followed by 2 redundant
king-position bytes and one castling-rights byte.

| Bytes | Meaning |
| --- | --- |
| 0..63 | square contents (one byte per square) |
| 64 | white king square (0..63) |
| 65 | black king square (0..63) |
| 66 | castling rights (low 4 bits, see [§1.1](#11-castling-rights-byte)) |

### 1.1 Castling-rights byte

| Bit | Mask | Meaning |
| --- | --- | --- |
| 0 | `0x01` | white kingside  (K) |
| 1 | `0x02` | white queenside (Q) |
| 2 | `0x04` | black kingside  (k) |
| 3 | `0x08` | black queenside (q) |
| 4..7 | `0xf0` | reserved, must be zero |

This is the same 4-flag encoding FEN uses for its `KQkq` field, packed into
4 bits of one byte. Initial value: `0x0f` (all four rights available).

A right is *cleared* when something happens that would invalidate it:
- the king of that color moves (clears both bits for that color);
- the relevant rook moves from its corner;
- something captures or otherwise lands on that corner.

There is **no separate "has castled" flag**: castling moves the king from
its home square, which the same rule already drains both rights for that
color. So "rights bit cleared" subsumes "already castled / king moved /
rook moved / rook captured" — the validator does not need to distinguish
those four causes, and a player who castled cannot castle again.

Each square byte encodes:

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

The king-position bytes are redundant with the square contents, but tracking
them explicitly avoids a 64-square scan for the king on every check
detection (see [§5.5](#55-check-detection)). The redundancy is enforced by
`boardOK` (start-of-game) and `kingPosOK` (per move).

Standard starting position:

```
rank 0 (white back):  R N B Q K B N R     -> white king at e1, sq=4
rank 1 (white pawns): P P P P P P P P
ranks 2..5:           empty
rank 6 (black pawns): p p p p p p p p
rank 7 (black back):  r n b q k b n r     -> black king at e8, sq=60
white king pos byte = 0x04
black king pos byte = 0x3c
castling rights byte = 0x0f (all four rights initially available)
```

## 2. Move encoding (5 bytes)

A move is a 5-byte tuple:

| Byte | Field | Notes |
| --- | --- | --- |
| 0 | from | 0..63 |
| 1 | to | 0..63 |
| 2 | piece | full byte: `color\|type` — same encoding as the board |
| 3 | flags | bit 0 (`0x01`) capture (validated against target square); bit 1 (`0x02`) check (recorded; **not** verified); bit 2 (`0x04`) checkmate (recorded; **not** verified); bit 3 (`0x08`) castling (validated, see [§3.5](#35-castling-move)) |
| 4 | reserved | must be `0x00` |

The check / checkmate flags are accepted as-is and not validated — verifying
them would require a full move-generation engine. They are kept in the spec
to mirror SAN/PGN conventions.

Bits 4..7 of the flags byte are reserved and must be zero — `wireOK`
rejects anything in `0xf0`. Capture and castling are mutually exclusive
(castling never captures); setting both at once causes `targetOK` to fail
because the destination of a castle is empty.

## 3. Functions exposed by the local script

The script exports five top-level functions; tests invoke them via wire
indices (toposort places no-deps fns first; `CompileLocalScriptWithIndex`
returns the source-symbol → wire-index mapping):

| Symbol | Purpose |
| --- | --- |
| `isStart(board)` | board equals the canonical starting position |
| `boardOK(board)` | board-level integrity (length + king-pos invariants) |
| `move(start, spec, result)` | individual-move legality + correct apply |
| `isCheck(kingColor, board)` | king of `kingColor` is currently under attack |
| `playerMove(kingColor, start, spec, result)` | full per-player turn predicate |

### `isStart(board)`

Returns truthy iff `board` byte-equals the canonical 66-byte starting
position. Implementation: a single `equal(board, 0x<66 hex bytes>)`.

### `boardOK(board)`

Returns truthy iff `board` is structurally valid as a game-state snapshot:
`len == 67`, both king-pos bytes are in `0..63`, the squares they index
hold a white king (`0x16`) and a black king (`0x26`) respectively, and the
castling-rights byte uses only the low 4 bits. The covenant should call
this once at game-start to validate the initial board; per-move integrity
is then preserved by `kingPosOK` and `crOK` inside `move`.

### `move(startBoard, moveSpec, resultBoard)`

Returns truthy iff the move described by `moveSpec` is legal in `startBoard`
**and** applying it produces `resultBoard`. Specifically:

#### (a) Wire-format checks
- `len(startBoard) == 67`
- `len(resultBoard) == 67`
- `len(moveSpec) == 5`
- `moveSpec[0]` (from) and `moveSpec[1]` (to) are both in 0..63
- `moveSpec[4]` is `0x00`
- `flags` only has valid bits set (lower 4 bits — `flags & 0xf0 == 0`)

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

#### (e) Resulting board (squares)
- For every square `s != from`, `s != to`: `byte(resultBoard, s) == byte(startBoard, s)`.
- `byte(resultBoard, from) == EMPTY`
- `byte(resultBoard, to) == moveSpec[2]` (the moving piece)

#### (f) Resulting board (king-position bytes)
`kingPosOK`:
- if `moveSpec[2] == 0x16` (white king): `byte(resultBoard, 64) == to`
  else: `byte(resultBoard, 64) == byte(startBoard, 64)`
- if `moveSpec[2] == 0x26` (black king): `byte(resultBoard, 65) == to`
  else: `byte(resultBoard, 65) == byte(startBoard, 65)`

#### (g) Resulting board (castling-rights byte)
`crOK`:
- `byte(resultBoard, 66) == byte(startBoard, 66) AND crMask(from) AND crMask(to)`

where `crMask(sq)` returns `0xff` for ordinary squares and a clear-mask for
the 6 special squares:

| sq | role | mask | clears |
| --- | --- | --- | --- |
| 4  | e1 (white king home)        | `0xfc` | WK + WQ |
| 7  | h1 (white kingside rook)    | `0xfe` | WK |
| 0  | a1 (white queenside rook)   | `0xfd` | WQ |
| 60 | e8 (black king home)        | `0xf3` | BK + BQ |
| 63 | h8 (black kingside rook)    | `0xfb` | BK |
| 56 | a8 (black queenside rook)   | `0xf7` | BQ |

The `from` mask handles "the king or rook moved off this square"; the `to`
mask handles "something landed on this corner" (capture of a corner rook,
or any move that lands there at all — once anything is on a8 the BQ rook
can no longer have stayed). Castling itself is naturally subsumed: the
king moves from e1/e8, so the from-mask drains both that color's rights.

`move` applies (a)..(g) for both ordinary moves and castling. (d)+(e) are
replaced by §3.5 below when the castling flag is set.

`move` deliberately does **not** verify whose turn it is, nor that the
mover does not leave their own king in check. Both are concerns of
`playerMove`.

#### 3.5 Castling move

When `flags & 0x08` is set, `move` skips (d)+(e) and runs `castleOK`
instead. `castleOK` dispatches on `(piece, from, to)` to one of four
predicates (white kingside / white queenside / black kingside / black
queenside). For *each* castle the rules are:

1. **Right available.** The matching bit in `byte(startBoard, 66)` is set.
2. **Rook at home.** The relevant rook (`0x14` or `0x24`) sits on its
   corner (h1/a1/h8/a8 depending on side).
3. **Path empty.** Squares between king and rook are empty in the start
   board:
   - kingside: 2 squares (f1+g1 / f8+g8);
   - queenside: 3 squares (b1+c1+d1 / b8+c8+d8).
4. **King not currently in check.** `not(isCheck(kingColor, startBoard))`.
5. **King's pass-through square not under attack.** The single square the
   king walks across:
   - kingside: f1 (white) or f8 (black);
   - queenside: d1 (white) or d8 (black).
   The destination square is **not** checked here — that's covered by the
   "no self-check" rule of `playerMove` on the resulting board.
6. **Result board.** All squares unchanged except the four involved in the
   castle (king home + king dest + rook home + rook dest). The king-pos
   byte and rights byte updates of (f)+(g) apply unchanged: the king-pos
   byte follows the king to its new square, and the rights byte loses
   both bits for the castling color via `crMask(from=e1/e8) = 0xfc/0xf3`.

Note: `targetOK` (the destination is empty) is reused from the common
path — a valid castle has an empty destination square, so this falls out.

Out of scope for §3.5: no Chess960 / Fischer Random support; no record of
*how* the right was lost (intentionally — see §1.1).

### `isCheck(kingColor, board)`

Returns truthy iff the king of color `kingColor` (`0x10` white, `0x20`
black) is currently attacked on `board`. See [§5.5](#55-check-detection)
for the implementation.

### `playerMove(kingColor, start, spec, result)`

The full per-player turn predicate. Returns truthy iff:
- the moving piece in `spec` has color `kingColor` (the player is
  moving their own piece — this is the only place the script enforces
  whose turn it is);
- `move(start, spec, result)` holds; and
- `not(isCheck(kingColor, result))` — the mover is not left in check.

Composition: `and(moverIsOurs, move(...), not(isCheck(kingColor, result)))`.
This is the predicate a covenant should evaluate to validate one half-move.

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
- `kingPosOK(start, result, to, piece)` — bytes 64/65 update consistently with the moving piece
- `crMask(sq)` / `crOK(start, result, from, to)` — castling-rights byte updates consistently (see [§3 (g)](#g-resulting-board-castling-rights-byte))

### Castling
- `chunkUnchanged(start, result, baseIdx)` — 8 consecutive squares byte-equal across start and result
- `chunksUnchangedExcept0` / `chunksUnchangedExcept7` — the 7 chunks not touched by white / black castling
- `castleResWK_chunk` / `castleResWQ_chunk` / `castleResBK_chunk` / `castleResBQ_chunk` — the touched chunk for each of the 4 castles
- `castleWK` / `castleWQ` / `castleBK` / `castleBQ` — full per-case predicates
- `castleCase(piece, from, to)` — returns 0 (none) / 1..4 (WK / WQ / BK / BQ)
- `castleOK(start, result, from, to, piece)` — `selectCaseByIndex` dispatch on `castleCase`

## 5.5 Check detection

`isCheck(kingColor, board)` returns truthy iff the king of `kingColor` is
attacked on `board`. The general shape is: read the king's square from the
appropriate king-pos byte, then OR over every potential attacker square the
predicate "does the piece of opposite color sitting there attack the king
square?".

The 64-way OR is implemented as 8 OR-chunks of 8, paralleling `resOK` —
this works around easyfl's 15-arg cap on `or`. It is evaluated unconditionally
across all 64 squares; empty squares and same-color squares short-circuit
to false inside `attackerAt`, so the cost is bounded.

Helpers:

- `pawnAttacks(piece, from, to)` — pawns attack diagonally forward only,
  irrespective of whether the target square is occupied. The "1 step
  forward / 2 steps from starting rank" pawn-move shape does **not**
  threaten the square it advances to, so we cannot reuse `isPawnMove`.
- `pieceAttacks(board, piece, from, to)` — dispatches on `typeOf(piece)`.
  For non-pawn pieces this is exactly the existing geometry helpers
  (`isKnightMove`, `isBishopMove`, `isRookMove`, `isQueenMove`,
  `isKingMove`); the bishop / rook / queen variants already include
  path-clear, which is correct for attack tests as well (sliding pieces
  are blocked by anything in between).
- `attackerAt(board, attackerColor, attackerSq, targetSq)` — `attackerSq`
  holds a non-empty piece of `attackerColor` and that piece attacks
  `targetSq`.
- `chunkAtt(board, attackerColor, targetSq, baseSq)` — OR of `attackerAt`
  over 8 consecutive squares from `baseSq`.
- `underAttack(board, attackerColor, targetSq)` — OR of 8 chunks → 64-way
  scan.
- `isCheck(kingColor, board)` — picks the right king-pos byte and the
  opposite color, then calls `underAttack`.

What is **not** modelled by `isCheck`:

- Discovered checks beyond the immediate attack geometry (e.g., a piece
  pinned to its own king does not attack — actually it does, attacks are
  geometric here, no pin tracking is needed for "is the king attacked
  *now*").
- En-passant attack pattern.
- Castling-through-check (out of scope along with castling itself).

## 6. Out of scope (v1 simplifications)

- **En passant.** Requires "last move" state.
- **Pawn promotion.** Requires extending the move encoding with a
  promotion-piece byte.
- **Chess960 / Fischer Random castling.** The four castling cases hard-
  code the standard king/rook home squares.
- 50-move rule, threefold repetition, insufficient material.
- **Stalemate / checkmate detection inside the script.** Both reduce to
  "the side to move has no legal move", which would require enumerating
  all candidate moves — non-trivial without loops. Instead, the
  surrounding covenant uses a deadline / time control to settle these
  cases: see [§9](#9-game-flow-at-the-covenant-level).

The `flags` byte in `moveSpec` still has bits for "check" and "checkmate"
mirroring SAN/PGN, but `move` accepts them as-is without verifying them.
The `playerMove` predicate enforces "no self-check" via `isCheck` on the
result board, which is the only check-related rule actually validated.

## 7. Test cases

Compile-once-eval-many: the local script is compiled and decoded once per
test (or once via testing helpers and reused).

### Starting position
- `isStart` on the canonical 66-byte start position → true
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

### Check detection
- Starting position → neither king is in check.
- White rook gives check on the e-file (clear file) → `isCheck(WHITE, b)`
  false, `isCheck(BLACK, b)` true.
- Same setup with a blocker between the rook and the black king →
  `isCheck(BLACK, b)` false.
- Black knight on f3 attacking white king on e1 → check.
- Black pawn on d2 attacking white king on e1 → check; black pawn on
  e2 (in front of the king) → **not** check (pawns do not attack forward).
- Bishop diagonal check; same diagonal blocked → not check.
- King-pos byte stale (points to wrong square) → `isCheck` answers about
  whatever sits on the indexed square; this is the contract — the
  covenant must keep king-pos bytes consistent via `boardOK` /
  `kingPosOK`.

### `playerMove`
- Legal move that doesn't expose own king → true.
- Legal move that exposes own king to a discovered check → false.
- Move with the wrong-color piece (e.g., white tries to move a black
  pawn) → false even if individually legal.

### Castling
- All four castles legal from a clean setup (rights set, rook home,
  path empty, no checks involved) → true; result has king + rook at
  the right post-castle squares, king-pos byte updated, both rights
  bits for that color cleared.
- Castle rejected when the matching rights bit is already cleared.
- Castle rejected when the path is blocked by any piece.
- Castle rejected when the king is currently in check.
- Castle rejected when the king's pass-through square is attacked
  (f1 / d1 / f8 / d8).
- Castle accepted by `move` but rejected by `playerMove` when the
  destination square is attacked (this falls under the standard
  no-self-check rule).
- Castle rejected when the rook is missing from its corner.
- Rights bookkeeping: a normal rook move from a corner clears the
  matching right; a normal king move clears both rights for that color;
  a capture (or any move) landing on a corner clears the matching right.
- Wire format: `flags = 0x18` (castle + reserved bit 4) is rejected by
  `wireOK`; `flags = 0x08` is accepted and validated by `castleOK`.
- `boardOK` rejects a board whose rights byte has any of bits 4..7 set.

## 8. Implementation plan

1. Generate the canonical 67-byte starting position (64 squares +
   king-pos bytes `0x04`, `0x3c` + rights byte `0x0f`) as a hex literal
   embedded in the local-script source for `isStart`.
2. Write the helper fns (`colorOf`, `typeOf`, ranks, files, `oppColor`, …) in
   EasyFL.
3. Write `isXxxMove` geometry checks, then `geometryOK` dispatch.
4. Write `pathClear` with 6 unrolled checks per direction.
5. Write `resOK`, `targetOK`, `sourceOK`, `wireOK`, `kingPosOK`,
   `boardOK`, `crMask`, `crOK`.
6. Write `pawnAttacks`, `pieceAttacks`, `attackerAt`, `chunkAtt`,
   `underAttack`, `isCheck`.
7. Write `chunkUnchanged` + the per-case castle-result chunks +
   `castleWK / WQ / BK / BQ` + `castleCase` + `castleOK`.
8. Tie it all together in `move()` (common rules + flag-bit-3 dispatch
   to `castleOK`) and `playerMove` on top.
9. Compile via `Library[T].CompileLocalScriptWithIndex` so tests can
   invoke functions by source-level name.

## 9. Game flow at the covenant level

These rules belong to the surrounding Proxima covenant, not to this script.
They are listed here so the script's public surface (`boardOK`, `move`,
`isCheck`, `playerMove`, `isStart`) is judged in context.

### 9.1 Setup and bounty
- The two players post a bounty into a single UTXO (the "game UTXO"), which
  carries the current 66-byte board, the side to move, and a per-move
  deadline. The covenant validates the initial board with `boardOK` (and
  optionally `isStart` for "play from the standard start").

### 9.2 A normal half-move
- The player whose turn it is consumes the game UTXO and produces a
  successor whose board is `result`, and whose side-to-move is flipped.
  The covenant requires `playerMove(myColor, oldBoard, spec, result)` to
  hold. That single predicate already covers (a)–(f) of `move`, "moving
  your own piece", and "do not leave own king in check".
- The deadline on the successor is shifted by the move-time budget.

### 9.3 No legal move = mate-or-deadline
- Detecting checkmate / stalemate inside the script would require
  enumerating all candidate moves; we don't do that. Instead the rule
  becomes:
  - If the side to move cannot produce a `playerMove` before the
    deadline, the game UTXO becomes consumable by the *opposite* side
    via a "deadline branch" of the covenant.
  - Whoever consumes via that branch claims the full bounty. This
    collapses both "checkmate" and "actual time-out" into the same
    on-chain rule — the player who is mated is, by definition, also a
    player who cannot make a `playerMove` and therefore loses on
    deadline. Stalemate falls into the same bucket; for v1 we accept
    that this rule is harsher than the FIDE rule (which awards a draw
    for stalemate).
- A symmetric branch handles the case where the wrong side tries to act
  on a deadline before it expires — that is rejected by the deadline
  predicate; only the player whose turn it is **not** can claim on
  deadline.

### 9.4 Tie by agreement
- A "tie proposal" branch lets the side to move emit a successor that is
  byte-for-byte the same board, with a `tieProposed` flag set and the
  deadline carried over.
- The opposite side, in their turn, may either play a normal `playerMove`
  (which clears `tieProposed`) or take a "tie accept" branch that splits
  the bounty equally and finalises the game.

### 9.5 Out of scope for v1 covenant
- 50-move rule and threefold repetition need history and would change the
  UTXO schema. They are not modelled.
- Castling, en passant, promotion follow the same fate as in the script
  itself (see [§6](#6-out-of-scope-v1-simplifications)) — adding them is
  a coordinated change to both the script and the move encoding.
