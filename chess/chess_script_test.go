// Package chess holds an EasyFL local-script chess move validator and the
// Go-side tests that exercise it. The script source lives in
// chess_script.easyfl (embedded via //go:embed); the design lives in
// chess_script.md.
//
// This is a stress test for the easyfl local-script feature, not a
// production chess engine — see chess_script.md §6 for the deliberate
// out-of-scope list (castling, en passant, promotion, turn alternation,
// check verification, …).
package chess

import (
	_ "embed"
	"testing"

	"github.com/lunfardo314/easyfl"
	"github.com/stretchr/testify/require"
)

//go:embed chess_script.easyfl
var chessScriptSource string

// =============================================================================
// Constants & Go-side board helpers
// =============================================================================

const (
	chEMPTY = 0x00
	chWHITE = 0x10
	chBLACK = 0x20

	chPAWN   = 0x01
	chKNIGHT = 0x02
	chBISHOP = 0x03
	chROOK   = 0x04
	chQUEEN  = 0x05
	chKING   = 0x06

	chWP = chWHITE | chPAWN
	chWN = chWHITE | chKNIGHT
	chWB = chWHITE | chBISHOP
	chWR = chWHITE | chROOK
	chWQ = chWHITE | chQUEEN
	chWK = chWHITE | chKING
	chBP = chBLACK | chPAWN
	chBN = chBLACK | chKNIGHT
	chBB = chBLACK | chBISHOP
	chBR = chBLACK | chROOK
	chBQ = chBLACK | chQUEEN
	chBK = chBLACK | chKING
)

func chSq(rank, file int) int { return rank*8 + file }

// Boards are 69 bytes: 64 squares + bytes 64 (white king sq), 65 (black
// king sq), 66 (castling rights, low 4 bits: WK WQ BK BQ), 67 (en-passant
// target sq: 0..63 if EP available, 0xff = none), 68 (side to move:
// 0x10 white / 0x20 black). See chess_script.md §1.
const chBoardLen = 69

// Castling-rights bit masks. Mirror chess_script.easyfl.
const (
	chCR_WK = 0x01 // white kingside
	chCR_WQ = 0x02 // white queenside
	chCR_BK = 0x04 // black kingside
	chCR_BQ = 0x08 // black queenside
	chCRAll = chCR_WK | chCR_WQ | chCR_BK | chCR_BQ // 0x0f
)

// chEPNone is the byte value used at index 67 when no en-passant capture
// is available for the next move. Anything outside 0..63 means "none";
// 0xff is the canonical sentinel (FEN-equivalent of "-").
const chEPNone = 0xff

// Move flag bits (mirror moveSpec[3] semantics).
const (
	chFlagCapture = 0x01
	chFlagCheck   = 0x02
	chFlagMate    = 0x04
	chFlagCastle  = 0x08
	chFlagEP      = 0x10
)

// chCRMask mirrors crMask in the easyfl source: clears the rights bit(s)
// for any move that touches one of the 6 special squares (king or rook
// home squares).
func chCRMask(sq int) byte {
	switch sq {
	case 4: // e1 (white king home)
		return 0xfc
	case 7: // h1 (white kingside rook home)
		return 0xfe
	case 0: // a1 (white queenside rook home)
		return 0xfd
	case 60: // e8 (black king home)
		return 0xf3
	case 63: // h8 (black kingside rook home)
		return 0xfb
	case 56: // a8 (black queenside rook home)
		return 0xf7
	default:
		return 0xff
	}
}

func chNewStartBoard() []byte {
	b := make([]byte, chBoardLen)
	// rank 0 (white back rank)
	b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7] = chWR, chWN, chWB, chWQ, chWK, chWB, chWN, chWR
	// rank 1 (white pawns)
	for i := 0; i < 8; i++ {
		b[8+i] = chWP
	}
	// ranks 2..5 stay 0x00
	// rank 6 (black pawns)
	for i := 0; i < 8; i++ {
		b[48+i] = chBP
	}
	// rank 7 (black back rank)
	b[56], b[57], b[58], b[59], b[60], b[61], b[62], b[63] = chBR, chBN, chBB, chBQ, chBK, chBB, chBN, chBR
	b[64] = byte(chSq(0, 4)) // white king at e1
	b[65] = byte(chSq(7, 4)) // black king at e8
	b[66] = chCRAll          // all four castling rights initially available
	b[67] = chEPNone         // no en-passant target on move 1
	b[68] = chWHITE          // white moves first
	return b
}

func chEmptyBoard() []byte {
	b := make([]byte, chBoardLen)
	b[67] = chEPNone // no EP target
	b[68] = chWHITE  // default: white to move
	return b
}

// chSet returns a copy of b with sq set to piece. If piece is a king, the
// matching king-pos byte is updated too — keeping the redundant king-pos
// bytes consistent with the squares is the caller's job, and this helper
// makes the common case automatic.
func chSet(b []byte, sq int, piece byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	out[sq] = piece
	switch piece {
	case chWK:
		out[64] = byte(sq)
	case chBK:
		out[65] = byte(sq)
	}
	return out
}

// chBoardWithKings returns an empty board with white and black kings
// placed at the given squares (king-pos bytes updated by chSet).
func chBoardWithKings(whiteKingSq, blackKingSq int) []byte {
	b := chSet(chEmptyBoard(), whiteKingSq, chWK)
	return chSet(b, blackKingSq, chBK)
}

func chMove(from, to int, piece, flags byte) []byte {
	return []byte{byte(from), byte(to), piece, flags, 0}
}

// chApply produces the result-board obtained by applying spec to start.
// Mirrors what move() expects: square moves (with promotion replacing the
// pawn on the destination), king-pos byte update on king moves, rights
// byte AND'd with the from/to masks, EP target updated (midpoint on a
// 2-square pawn push, else 0xff), and side-to-move byte flipped. Castling
// also moves the rook; en-passant also clears the captured pawn square.
func chApply(start, spec []byte) []byte {
	out := make([]byte, len(start))
	copy(out, start)
	from, to, piece, flags, promote := spec[0], spec[1], spec[2], spec[3], spec[4]

	// Effective piece landing on `to`: promotion piece if this is a
	// promoting pawn move, otherwise the pawn / piece itself.
	effective := piece
	if (piece&0x0f) == chPAWN && chIsBackRank(piece, int(to)) && promote != 0 {
		effective = promote
	}

	out[from] = chEMPTY
	out[to] = effective

	if flags&chFlagCastle != 0 {
		// Castling: also move the rook.
		var rookFrom, rookTo int
		var rook byte
		switch {
		case from == byte(chSq(0, 4)) && to == byte(chSq(0, 6)): // white kingside
			rookFrom, rookTo, rook = chSq(0, 7), chSq(0, 5), chWR
		case from == byte(chSq(0, 4)) && to == byte(chSq(0, 2)): // white queenside
			rookFrom, rookTo, rook = chSq(0, 0), chSq(0, 3), chWR
		case from == byte(chSq(7, 4)) && to == byte(chSq(7, 6)): // black kingside
			rookFrom, rookTo, rook = chSq(7, 7), chSq(7, 5), chBR
		case from == byte(chSq(7, 4)) && to == byte(chSq(7, 2)): // black queenside
			rookFrom, rookTo, rook = chSq(7, 0), chSq(7, 3), chBR
		}
		out[rookFrom] = chEMPTY
		out[rookTo] = rook
	}

	if flags&chFlagEP != 0 && (piece&0x0f) == chPAWN {
		// En-passant: the captured pawn sits adjacent to `to` on the
		// rank where the capturer started. White EP captures down a rank
		// (to-8); black up a rank (to+8). Guarded by piece==pawn so a
		// malformed spec (EP bit on a non-pawn move) doesn't index OOB.
		var capturedSq int
		if piece&0xf0 == chWHITE {
			capturedSq = int(to) - 8
		} else {
			capturedSq = int(to) + 8
		}
		if capturedSq >= 0 && capturedSq < 64 {
			out[capturedSq] = chEMPTY
		}
	}

	switch piece {
	case chWK:
		out[64] = to
	case chBK:
		out[65] = to
	}

	if len(out) > 66 {
		out[66] = start[66] & chCRMask(int(from)) & chCRMask(int(to))
	}

	// EP target byte: midpoint of a 2-square pawn push, else "none".
	if len(out) > 67 {
		if (piece&0x0f) == chPAWN && chAbsDiff(int(from)/8, int(to)/8) == 2 {
			out[67] = byte((int(from) + int(to)) / 2)
		} else {
			out[67] = chEPNone
		}
	}

	// Side flip.
	if len(out) > 68 {
		if start[68] == chWHITE {
			out[68] = chBLACK
		} else {
			out[68] = chWHITE
		}
	}
	return out
}

// chIsBackRank: `to` is the promotion rank for `piece`'s color (rank 7
// for white, rank 0 for black).
func chIsBackRank(piece byte, sq int) bool {
	rank := sq / 8
	if piece&0xf0 == chWHITE {
		return rank == 7
	}
	return rank == 0
}

func chAbsDiff(a, b int) int {
	if a < b {
		return b - a
	}
	return a - b
}

// =============================================================================
// Test harness: load and index the chess script
// =============================================================================

type chessHarness struct {
	lib     *easyfl.Library[any]
	script  *easyfl.LocalScript[any]
	indices map[string]int
}

func (c *chessHarness) call(t testing.TB, sym string, args ...[]byte) []byte {
	t.Helper()
	idx, ok := c.indices[sym]
	require.True(t, ok, "unknown symbol %q", sym)
	got, err := c.script.Eval(nil, idx, args...)
	require.NoError(t, err)
	return got
}

func loadChessScript(t testing.TB) *chessHarness {
	t.Helper()
	lib := easyfl.NewBaseLibrary[any]()
	bin, indices, err := lib.CompileLocalScriptWithIndex(chessScriptSource)
	require.NoError(t, err)
	t.Logf("chess script: %d bytes, %d functions", len(bin), len(indices))
	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
	return &chessHarness{lib: lib, script: s, indices: indices}
}

// =============================================================================
// Tests: isStart
// =============================================================================

func TestChess_isStart_StandardPosition(t *testing.T) {
	h := loadChessScript(t)
	require.NotEmpty(t, h.call(t, "isStart", chNewStartBoard()))
}

func TestChess_isStart_Tampered(t *testing.T) {
	h := loadChessScript(t)
	b := chNewStartBoard()
	b[16] = chWP // extra white pawn on a3
	require.Empty(t, h.call(t, "isStart", b))
}

func TestChess_isStart_WrongLength(t *testing.T) {
	h := loadChessScript(t)
	require.Empty(t, h.call(t, "isStart", chNewStartBoard()[:chBoardLen-1]))
}

// =============================================================================
// Tests: move() — pawn
// =============================================================================

func TestChess_PawnE2E4(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	e2, e4 := chSq(1, 4), chSq(3, 4)
	spec := chMove(e2, e4, chWP, 0)
	require.NotEmpty(t, h.call(t, "move", start, spec, chApply(start, spec)))
}

func TestChess_PawnE2E3(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	e2, e3 := chSq(1, 4), chSq(2, 4)
	spec := chMove(e2, e3, chWP, 0)
	require.NotEmpty(t, h.call(t, "move", start, spec, chApply(start, spec)))
}

func TestChess_PawnDoubleStepNotFromRank2(t *testing.T) {
	h := loadChessScript(t)
	// Set up a pawn at e3 (not on the starting rank).
	start := chSet(chEmptyBoard(), chSq(2, 4), chWP)
	spec := chMove(chSq(2, 4), chSq(4, 4), chWP, 0)
	require.Empty(t, h.call(t, "move", start, spec, chApply(start, spec)))
}

func TestChess_PawnDoubleStepBlocked(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	// Block e3 with a black knight.
	start = chSet(start, chSq(2, 4), chBN)
	spec := chMove(chSq(1, 4), chSq(3, 4), chWP, 0)
	require.Empty(t, h.call(t, "move", start, spec, chApply(start, spec)))
}

func TestChess_PawnForwardOntoOccupiedRejected(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	// Place a black piece directly in front of the e-pawn.
	start = chSet(start, chSq(2, 4), chBP)
	spec := chMove(chSq(1, 4), chSq(2, 4), chWP, 0)
	require.Empty(t, h.call(t, "move", start, spec, chApply(start, spec)))
}

func TestChess_PawnDiagonalCapture(t *testing.T) {
	h := loadChessScript(t)
	// White pawn on e4; black pawn on d5; capture exd5.
	b := chSet(chEmptyBoard(), chSq(3, 4), chWP)
	b = chSet(b, chSq(4, 3), chBP)
	from, to := chSq(3, 4), chSq(4, 3)
	spec := chMove(from, to, chWP, 0x01) // capture flag set
	require.NotEmpty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_PawnDiagonalCaptureOfSameColorRejected(t *testing.T) {
	h := loadChessScript(t)
	b := chSet(chEmptyBoard(), chSq(3, 4), chWP)
	b = chSet(b, chSq(4, 3), chWN) // own knight on d5
	spec := chMove(chSq(3, 4), chSq(4, 3), chWP, 0x01)
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_PawnDiagonalCaptureNoTargetRejected(t *testing.T) {
	h := loadChessScript(t)
	b := chSet(chEmptyBoard(), chSq(3, 4), chWP)
	spec := chMove(chSq(3, 4), chSq(4, 3), chWP, 0x01)
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_BlackPawnDoubleStep(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	from, to := chSq(6, 4), chSq(4, 4) // e7-e5
	spec := chMove(from, to, chBP, 0)
	require.NotEmpty(t, h.call(t, "move", start, spec, chApply(start, spec)))
}

// =============================================================================
// Tests: move() — knight, bishop, rook, queen, king
// =============================================================================

func TestChess_KnightAllEightLShapes(t *testing.T) {
	h := loadChessScript(t)
	// Knight at d4 on an otherwise-empty board.
	from := chSq(3, 3)
	deltas := [][2]int{
		{+1, +2}, {+1, -2}, {-1, +2}, {-1, -2},
		{+2, +1}, {+2, -1}, {-2, +1}, {-2, -1},
	}
	for _, d := range deltas {
		to := chSq(3+d[0], 3+d[1])
		b := chSet(chEmptyBoard(), from, chWN)
		spec := chMove(from, to, chWN, 0)
		require.NotEmpty(t, h.call(t, "move", b, spec, chApply(b, spec)),
			"delta=%v from=%d to=%d", d, from, to)
	}
}

func TestChess_KnightOntoSameColorRejected(t *testing.T) {
	h := loadChessScript(t)
	from, to := chSq(3, 3), chSq(5, 4)
	b := chSet(chEmptyBoard(), from, chWN)
	b = chSet(b, to, chWP)
	spec := chMove(from, to, chWN, 0)
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_KnightCaptures(t *testing.T) {
	h := loadChessScript(t)
	from, to := chSq(3, 3), chSq(5, 4)
	b := chSet(chEmptyBoard(), from, chWN)
	b = chSet(b, to, chBP)
	spec := chMove(from, to, chWN, 0x01)
	require.NotEmpty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_BishopClearDiagonal(t *testing.T) {
	h := loadChessScript(t)
	from, to := chSq(0, 2), chSq(5, 7) // c1-h6 (NE)
	b := chSet(chEmptyBoard(), from, chWB)
	spec := chMove(from, to, chWB, 0)
	require.NotEmpty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_BishopBlocked(t *testing.T) {
	h := loadChessScript(t)
	from, to := chSq(0, 2), chSq(5, 7)
	b := chSet(chEmptyBoard(), from, chWB)
	b = chSet(b, chSq(2, 4), chBP) // e3 in the way
	spec := chMove(from, to, chWB, 0)
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_RookClearFile(t *testing.T) {
	h := loadChessScript(t)
	from, to := chSq(0, 0), chSq(7, 0) // a1-a8
	b := chSet(chEmptyBoard(), from, chWR)
	spec := chMove(from, to, chWR, 0)
	require.NotEmpty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_RookBlockedByPiece(t *testing.T) {
	h := loadChessScript(t)
	from, to := chSq(0, 0), chSq(7, 0)
	b := chSet(chEmptyBoard(), from, chWR)
	b = chSet(b, chSq(3, 0), chBP) // a4 blocks
	spec := chMove(from, to, chWR, 0)
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_QueenLikeBishopAndLikeRook(t *testing.T) {
	h := loadChessScript(t)
	// Queen at d4, move along rank to h4 (rook-like).
	from, to1 := chSq(3, 3), chSq(3, 7)
	b := chSet(chEmptyBoard(), from, chWQ)
	spec1 := chMove(from, to1, chWQ, 0)
	require.NotEmpty(t, h.call(t, "move", b, spec1, chApply(b, spec1)))

	// Queen at d4, move diagonal to a7 (bishop-like).
	to2 := chSq(6, 0)
	spec2 := chMove(from, to2, chWQ, 0)
	require.NotEmpty(t, h.call(t, "move", b, spec2, chApply(b, spec2)))
}

func TestChess_KingOneSquareInAllDirections(t *testing.T) {
	h := loadChessScript(t)
	from := chSq(3, 3)
	for _, d := range [][2]int{
		{+1, 0}, {-1, 0}, {0, +1}, {0, -1},
		{+1, +1}, {+1, -1}, {-1, +1}, {-1, -1},
	} {
		to := chSq(3+d[0], 3+d[1])
		b := chSet(chEmptyBoard(), from, chWK)
		spec := chMove(from, to, chWK, 0)
		require.NotEmpty(t, h.call(t, "move", b, spec, chApply(b, spec)),
			"delta=%v", d)
	}
}

func TestChess_KingTwoSquaresRejected(t *testing.T) {
	h := loadChessScript(t)
	from, to := chSq(3, 3), chSq(3, 5)
	b := chSet(chEmptyBoard(), from, chWK)
	spec := chMove(from, to, chWK, 0)
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

// =============================================================================
// Tests: result-board consistency
// =============================================================================

func TestChess_ResultBoardWrong(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	spec := chMove(chSq(1, 4), chSq(3, 4), chWP, 0)
	good := chApply(start, spec)

	// Tamper with an unrelated square.
	bad := make([]byte, 64)
	copy(bad, good)
	bad[chSq(0, 0)] = chEMPTY // removed white rook from a1
	require.Empty(t, h.call(t, "move", start, spec, bad))

	// from-square not cleared.
	bad2 := make([]byte, 64)
	copy(bad2, good)
	bad2[spec[0]] = chWP
	require.Empty(t, h.call(t, "move", start, spec, bad2))

	// to-square has wrong piece.
	bad3 := make([]byte, 64)
	copy(bad3, good)
	bad3[spec[1]] = chWN
	require.Empty(t, h.call(t, "move", start, spec, bad3))
}

// =============================================================================
// Tests: wire-format negatives
// =============================================================================

func TestChess_WireFormatBadLengths(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	spec := chMove(chSq(1, 4), chSq(3, 4), chWP, 0)
	good := chApply(start, spec)

	// Wrong start length.
	require.Empty(t, h.call(t, "move", start[:chBoardLen-1], spec, good))
	// Wrong result length.
	require.Empty(t, h.call(t, "move", start, spec, good[:chBoardLen-1]))
	// Wrong moveSpec length.
	require.Empty(t, h.call(t, "move", start, spec[:4], good))
}

func TestChess_WireFormatReservedNotZero(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	spec := chMove(chSq(1, 4), chSq(3, 4), chWP, 0)
	spec[4] = 0xff
	good := chApply(start, spec)
	require.Empty(t, h.call(t, "move", start, spec, good))
}

func TestChess_WireFormatBadFlags(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	spec := chMove(chSq(1, 4), chSq(3, 4), chWP, 0x20) // bit 5, reserved
	good := chApply(start, spec)
	require.Empty(t, h.call(t, "move", start, spec, good))
}

// =============================================================================
// Tests: sample game (smoke: 3 moves per side, played in sequence)
// =============================================================================

func TestChess_SampleGame_SpanishOpening(t *testing.T) {
	h := loadChessScript(t)
	// 1. e4    e5
	// 2. Nf3   Nc6
	// 3. Bb5   a6
	moves := []struct {
		sym   string
		from  int
		to    int
		piece byte
		flags byte
	}{
		{"1. e4", chSq(1, 4), chSq(3, 4), chWP, 0},
		{"1...e5", chSq(6, 4), chSq(4, 4), chBP, 0},
		{"2. Nf3", chSq(0, 6), chSq(2, 5), chWN, 0},
		{"2...Nc6", chSq(7, 1), chSq(5, 2), chBN, 0},
		{"3. Bb5", chSq(0, 5), chSq(4, 1), chWB, 0},
		{"3...a6", chSq(6, 0), chSq(5, 0), chBP, 0},
	}
	board := chNewStartBoard()
	for _, m := range moves {
		spec := chMove(m.from, m.to, m.piece, m.flags)
		next := chApply(board, spec)
		got := h.call(t, "move", board, spec, next)
		require.NotEmpty(t, got, "move %q rejected", m.sym)
		board = next
	}
}

// =============================================================================
// Tests: boardOK (king-pos invariants)
// =============================================================================

func TestChess_BoardOK_StartingPosition(t *testing.T) {
	h := loadChessScript(t)
	require.NotEmpty(t, h.call(t, "boardOK", chNewStartBoard()))
}

func TestChess_BoardOK_EmptyHasNoKings(t *testing.T) {
	h := loadChessScript(t)
	// All-zero board: king-pos bytes point at sq 0, but sq 0 is empty (not
	// a king of either color), so boardOK must reject.
	require.Empty(t, h.call(t, "boardOK", chEmptyBoard()))
}

func TestChess_BoardOK_KingPosByteOutOfRange(t *testing.T) {
	h := loadChessScript(t)
	b := chBoardWithKings(chSq(0, 4), chSq(7, 4))
	b[64] = 64 // out of range
	require.Empty(t, h.call(t, "boardOK", b))
}

func TestChess_BoardOK_KingPosByteMisaligned(t *testing.T) {
	h := loadChessScript(t)
	b := chBoardWithKings(chSq(0, 4), chSq(7, 4))
	b[64] = byte(chSq(0, 0)) // claims white king is at a1, but a1 is empty
	require.Empty(t, h.call(t, "boardOK", b))
}

// =============================================================================
// Tests: isCheck
// =============================================================================

func TestChess_IsCheck_StartingPositionNeitherInCheck(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	require.Empty(t, h.call(t, "isCheck", []byte{chWHITE}, start),
		"white king must not be in check at the start")
	require.Empty(t, h.call(t, "isCheck", []byte{chBLACK}, start),
		"black king must not be in check at the start")
}

func TestChess_IsCheck_RookOnClearFile(t *testing.T) {
	h := loadChessScript(t)
	// White king a1, black king e8, white rook e1: rook attacks black king
	// up the clear e-file.
	b := chBoardWithKings(chSq(0, 0), chSq(7, 4))
	b = chSet(b, chSq(0, 4), chWR)
	require.NotEmpty(t, h.call(t, "isCheck", []byte{chBLACK}, b),
		"black king must be in check from the rook on e1")
	require.Empty(t, h.call(t, "isCheck", []byte{chWHITE}, b),
		"white king has no attackers")
}

func TestChess_IsCheck_RookBlocked(t *testing.T) {
	h := loadChessScript(t)
	b := chBoardWithKings(chSq(0, 0), chSq(7, 4))
	b = chSet(b, chSq(0, 4), chWR)
	b = chSet(b, chSq(3, 4), chWP) // white pawn on e4 blocks the file
	require.Empty(t, h.call(t, "isCheck", []byte{chBLACK}, b))
}

func TestChess_IsCheck_KnightFork(t *testing.T) {
	h := loadChessScript(t)
	// White knight on f3 attacks e1 (and other L-shape squares). Place the
	// black king on e1 so it sits on one of those squares.
	b := chBoardWithKings(chSq(7, 0), chSq(0, 4)) // wK a8, bK e1
	b = chSet(b, chSq(2, 5), chWN)                // wN f3
	require.NotEmpty(t, h.call(t, "isCheck", []byte{chBLACK}, b))
	require.Empty(t, h.call(t, "isCheck", []byte{chWHITE}, b))
}

func TestChess_IsCheck_PawnDiagonalAttack(t *testing.T) {
	h := loadChessScript(t)
	// White pawn on d7 attacks e8 (diagonal forward). Black king on e8.
	b := chBoardWithKings(chSq(0, 0), chSq(7, 4))
	b = chSet(b, chSq(6, 3), chWP)
	require.NotEmpty(t, h.call(t, "isCheck", []byte{chBLACK}, b))
}

func TestChess_IsCheck_PawnInFrontIsNotCheck(t *testing.T) {
	h := loadChessScript(t)
	// Black pawn directly in front of white king. Pawns do not attack
	// forward, so the king is not in check.
	b := chBoardWithKings(chSq(0, 4), chSq(7, 0)) // wK e1, bK a8
	b = chSet(b, chSq(1, 4), chBP)                // bP e2
	require.Empty(t, h.call(t, "isCheck", []byte{chWHITE}, b))
}

func TestChess_IsCheck_BishopDiagonal(t *testing.T) {
	h := loadChessScript(t)
	// White bishop a1 → black king h8: long diagonal clear.
	b := chBoardWithKings(chSq(0, 4), chSq(7, 7))
	b = chSet(b, chSq(0, 0), chWB)
	require.NotEmpty(t, h.call(t, "isCheck", []byte{chBLACK}, b))
}

func TestChess_IsCheck_BishopBlocked(t *testing.T) {
	h := loadChessScript(t)
	b := chBoardWithKings(chSq(0, 4), chSq(7, 7))
	b = chSet(b, chSq(0, 0), chWB)
	b = chSet(b, chSq(3, 3), chBP) // d4 blocks the diagonal
	require.Empty(t, h.call(t, "isCheck", []byte{chBLACK}, b))
}

func TestChess_IsCheck_QueenLikeBishopAndRook(t *testing.T) {
	h := loadChessScript(t)
	// White queen attacking black king diagonally (a1 → h8).
	b := chBoardWithKings(chSq(0, 4), chSq(7, 7))
	b = chSet(b, chSq(0, 0), chWQ)
	require.NotEmpty(t, h.call(t, "isCheck", []byte{chBLACK}, b))

	// Same queen, but now the black king is on a8 (rook-like along a-file).
	b2 := chBoardWithKings(chSq(0, 4), chSq(7, 0))
	b2 = chSet(b2, chSq(0, 0), chWQ)
	require.NotEmpty(t, h.call(t, "isCheck", []byte{chBLACK}, b2))
}

// =============================================================================
// Tests: playerMove (full per-player turn predicate)
// =============================================================================

func TestChess_PlayerMove_LegalFromStart(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	spec := chMove(chSq(1, 4), chSq(3, 4), chWP, 0) // 1. e4
	require.NotEmpty(t, h.call(t, "playerMove",
		[]byte{chWHITE}, start, spec, chApply(start, spec)))
}

func TestChess_PlayerMove_WrongColorRejected(t *testing.T) {
	h := loadChessScript(t)
	// White claims to move on its own turn but the spec carries a black
	// pawn. The move would be individually legal for black; playerMove must
	// still reject because the moving piece is not white's.
	start := chNewStartBoard()
	spec := chMove(chSq(6, 4), chSq(4, 4), chBP, 0)
	require.Empty(t, h.call(t, "playerMove",
		[]byte{chWHITE}, start, spec, chApply(start, spec)))
}

func TestChess_PlayerMove_LeavesOwnKingInCheckRejected(t *testing.T) {
	h := loadChessScript(t)
	// White king e1, white rook e3 (the only thing blocking the e-file),
	// black rook e8. Moving the rook off the e-file exposes the king.
	b := chBoardWithKings(chSq(0, 4), chSq(7, 0)) // wK e1, bK a8
	b = chSet(b, chSq(2, 4), chWR)                // wR e3
	b = chSet(b, chSq(7, 4), chBR)                // bR e8
	spec := chMove(chSq(2, 4), chSq(2, 0), chWR, 0) // Re3-a3
	res := chApply(b, spec)

	require.NotEmpty(t, h.call(t, "move", b, spec, res),
		"the move itself is geometrically legal")
	require.Empty(t, h.call(t, "playerMove",
		[]byte{chWHITE}, b, spec, res),
		"playerMove must reject moves that leave the mover in check")
}

func TestChess_PlayerMove_CapturingTheThreatIsLegal(t *testing.T) {
	h := loadChessScript(t)
	// Same pinning setup, but white captures the threatening rook on e8.
	// After the capture, no black piece can attack e1 — playerMove
	// accepts.
	b := chBoardWithKings(chSq(0, 4), chSq(7, 0))
	b = chSet(b, chSq(2, 4), chWR)
	b = chSet(b, chSq(7, 4), chBR)
	spec := chMove(chSq(2, 4), chSq(7, 4), chWR, 0x01) // Rxe8
	require.NotEmpty(t, h.call(t, "playerMove",
		[]byte{chWHITE}, b, spec, chApply(b, spec)))
}

func TestChess_PlayerMove_KingMoveUpdatesPosByte(t *testing.T) {
	h := loadChessScript(t)
	// White king walks one square. The king-pos byte must follow; chApply
	// already does this, so the move passes kingPosOK and (with no black
	// pieces around) playerMove.
	b := chBoardWithKings(chSq(0, 4), chSq(7, 0)) // wK e1, bK a8
	spec := chMove(chSq(0, 4), chSq(1, 4), chWK, 0)
	res := chApply(b, spec)
	require.Equal(t, byte(chSq(1, 4)), res[64], "king-pos byte updated")
	require.NotEmpty(t, h.call(t, "playerMove",
		[]byte{chWHITE}, b, spec, res))
}

// =============================================================================
// Tests: castling
// =============================================================================

// chCastleSetup returns a minimal board for testing one castle:
// white king at e1, black king at a8 (out of the way), and the white rook
// the test cares about placed on its home square. Rights start at chCRAll.
// Caller adds extra pieces / clears rights / etc. before invoking move.
func chCastleSetup(extraPieces ...struct {
	sq    int
	piece byte
}) []byte {
	b := chBoardWithKings(chSq(0, 4), chSq(7, 0)) // wK e1, bK a8
	for _, p := range extraPieces {
		b = chSet(b, p.sq, p.piece)
	}
	b[66] = chCRAll
	return b
}

func TestChess_Castling_WhiteKingsideLegal(t *testing.T) {
	h := loadChessScript(t)
	b := chCastleSetup(struct {
		sq    int
		piece byte
	}{chSq(0, 7), chWR}) // wR h1
	spec := chMove(chSq(0, 4), chSq(0, 6), chWK, 0x08)
	res := chApply(b, spec)
	require.NotEmpty(t, h.call(t, "playerMove",
		[]byte{chWHITE}, b, spec, res))
	require.Equal(t, byte(chWK), res[chSq(0, 6)], "king on g1")
	require.Equal(t, byte(chWR), res[chSq(0, 5)], "rook on f1")
	require.Equal(t, byte(chEMPTY), res[chSq(0, 4)], "e1 empty")
	require.Equal(t, byte(chEMPTY), res[chSq(0, 7)], "h1 empty")
	require.Equal(t, byte(chSq(0, 6)), res[64], "king-pos byte updated to g1")
	require.Equal(t, byte(chCR_BK|chCR_BQ), res[66],
		"both white rights cleared, black rights preserved")
}

func TestChess_Castling_WhiteQueensideLegal(t *testing.T) {
	h := loadChessScript(t)
	b := chCastleSetup(struct {
		sq    int
		piece byte
	}{chSq(0, 0), chWR}) // wR a1
	spec := chMove(chSq(0, 4), chSq(0, 2), chWK, 0x08)
	res := chApply(b, spec)
	require.NotEmpty(t, h.call(t, "playerMove",
		[]byte{chWHITE}, b, spec, res))
	require.Equal(t, byte(chWK), res[chSq(0, 2)], "king on c1")
	require.Equal(t, byte(chWR), res[chSq(0, 3)], "rook on d1")
	require.Equal(t, byte(chEMPTY), res[chSq(0, 0)], "a1 empty")
	require.Equal(t, byte(chEMPTY), res[chSq(0, 4)], "e1 empty")
	require.Equal(t, byte(chSq(0, 2)), res[64], "king-pos byte updated to c1")
	require.Equal(t, byte(chCR_BK|chCR_BQ), res[66])
}

func TestChess_Castling_BlackKingsideLegal(t *testing.T) {
	h := loadChessScript(t)
	// Black to castle. Place white king out of the way (a1) and black king
	// at e8.
	b := chBoardWithKings(chSq(0, 0), chSq(7, 4))
	b = chSet(b, chSq(7, 7), chBR) // bR h8
	b[66] = chCRAll
	b[68] = chBLACK
	spec := chMove(chSq(7, 4), chSq(7, 6), chBK, 0x08)
	res := chApply(b, spec)
	require.NotEmpty(t, h.call(t, "playerMove",
		[]byte{chBLACK}, b, spec, res))
	require.Equal(t, byte(chBK), res[chSq(7, 6)])
	require.Equal(t, byte(chBR), res[chSq(7, 5)])
	require.Equal(t, byte(chSq(7, 6)), res[65])
	require.Equal(t, byte(chCR_WK|chCR_WQ), res[66],
		"both black rights cleared, white rights preserved")
}

func TestChess_Castling_BlackQueensideLegal(t *testing.T) {
	h := loadChessScript(t)
	b := chBoardWithKings(chSq(0, 0), chSq(7, 4))
	b = chSet(b, chSq(7, 0), chBR) // bR a8
	b[66] = chCRAll
	b[68] = chBLACK
	spec := chMove(chSq(7, 4), chSq(7, 2), chBK, 0x08)
	res := chApply(b, spec)
	require.NotEmpty(t, h.call(t, "playerMove",
		[]byte{chBLACK}, b, spec, res))
	require.Equal(t, byte(chBK), res[chSq(7, 2)])
	require.Equal(t, byte(chBR), res[chSq(7, 3)])
}

func TestChess_Castling_RightAlreadyLost(t *testing.T) {
	h := loadChessScript(t)
	b := chCastleSetup(struct {
		sq    int
		piece byte
	}{chSq(0, 7), chWR})
	b[66] = chCRAll & ^byte(chCR_WK) // WK right cleared
	spec := chMove(chSq(0, 4), chSq(0, 6), chWK, 0x08)
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)),
		"castling without the rights bit must be rejected")
}

func TestChess_Castling_PathBlocked(t *testing.T) {
	h := loadChessScript(t)
	b := chCastleSetup(
		struct {
			sq    int
			piece byte
		}{chSq(0, 7), chWR}, // wR h1
		struct {
			sq    int
			piece byte
		}{chSq(0, 5), chWN}, // wN f1 blocks
	)
	spec := chMove(chSq(0, 4), chSq(0, 6), chWK, 0x08)
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_Castling_KingInCheckRejected(t *testing.T) {
	h := loadChessScript(t)
	// Black rook on e2 attacks white king on e1 — king is currently in
	// check and cannot castle.
	b := chCastleSetup(
		struct {
			sq    int
			piece byte
		}{chSq(0, 7), chWR}, // wR h1
		struct {
			sq    int
			piece byte
		}{chSq(1, 4), chBR}, // bR e2 attacks e1
	)
	spec := chMove(chSq(0, 4), chSq(0, 6), chWK, 0x08)
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_Castling_PassThroughCheckRejected(t *testing.T) {
	h := loadChessScript(t)
	// Black rook on f8 attacks f1 — the king's pass-through square for
	// kingside castling. King is not currently in check, but it would walk
	// through an attacked square.
	b := chCastleSetup(
		struct {
			sq    int
			piece byte
		}{chSq(0, 7), chWR}, // wR h1
		struct {
			sq    int
			piece byte
		}{chSq(7, 5), chBR}, // bR f8 attacks f1
	)
	spec := chMove(chSq(0, 4), chSq(0, 6), chWK, 0x08)
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_Castling_DestinationCheckRejectedByPlayerMove(t *testing.T) {
	h := loadChessScript(t)
	// Black rook on g8 attacks g1 — king's destination for kingside
	// castling. move() itself doesn't check the destination (it's the same
	// rule as "no self-check after move"); playerMove rejects via isCheck
	// on the result.
	b := chCastleSetup(
		struct {
			sq    int
			piece byte
		}{chSq(0, 7), chWR},
		struct {
			sq    int
			piece byte
		}{chSq(7, 6), chBR}, // bR g8 attacks g1
	)
	spec := chMove(chSq(0, 4), chSq(0, 6), chWK, 0x08)
	res := chApply(b, spec)
	require.NotEmpty(t, h.call(t, "move", b, spec, res),
		"move alone accepts (destination check is playerMove's job)")
	require.Empty(t, h.call(t, "playerMove",
		[]byte{chWHITE}, b, spec, res))
}

func TestChess_Castling_RookMissingRejected(t *testing.T) {
	h := loadChessScript(t)
	// Rights bit claims castling is still available, but the rook is not
	// on h1. (Stale-state stress: a buggy covenant could try to castle.)
	b := chCastleSetup() // no rook placed
	spec := chMove(chSq(0, 4), chSq(0, 6), chWK, 0x08)
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_Castling_RightsClearedOnRookMove(t *testing.T) {
	h := loadChessScript(t)
	// Move the h1 rook one step north. The move itself is legal; the
	// kingside castling right must be cleared.
	b := chCastleSetup(struct {
		sq    int
		piece byte
	}{chSq(0, 7), chWR})
	spec := chMove(chSq(0, 7), chSq(1, 7), chWR, 0)
	res := chApply(b, spec)
	require.NotEmpty(t, h.call(t, "move", b, spec, res))
	require.Equal(t, byte(chCRAll&^chCR_WK), res[66],
		"WK right cleared because the kingside rook moved")
}

func TestChess_Castling_RightsClearedOnKingMove(t *testing.T) {
	h := loadChessScript(t)
	// Just walk the king one square. Both white rights must clear.
	b := chCastleSetup()
	spec := chMove(chSq(0, 4), chSq(1, 4), chWK, 0)
	res := chApply(b, spec)
	require.NotEmpty(t, h.call(t, "move", b, spec, res))
	require.Equal(t, byte(chCR_BK|chCR_BQ), res[66])
}

func TestChess_Castling_CaptureOnCornerClearsRight(t *testing.T) {
	h := loadChessScript(t)
	// A piece lands on a8. Even if there's no rook there (covenant might
	// have placed an enemy on it), the BQ right must clear — once anything
	// has touched a8, that rook can't have stayed put.
	b := chBoardWithKings(chSq(0, 4), chSq(7, 4)) // wK e1, bK e8
	b = chSet(b, chSq(7, 0), chBR)                // bR a8
	b = chSet(b, chSq(5, 1), chWN)                // wN b6
	b[66] = chCRAll
	spec := chMove(chSq(5, 1), chSq(7, 0), chWN, 0x01) // Nxa8
	res := chApply(b, spec)
	require.NotEmpty(t, h.call(t, "move", b, spec, res))
	require.Equal(t, byte(chCRAll&^chCR_BQ), res[66])
}

func TestChess_Castling_FlagsByteRejectsHighBitsButAllowsCastleBit(t *testing.T) {
	h := loadChessScript(t)
	// Bits 5..7 (mask 0xe0) are reserved — wireOK must reject. Bit 3
	// (0x08, castle) alone must pass wireOK and is then validated by
	// castleOK.
	b := chCastleSetup(struct {
		sq    int
		piece byte
	}{chSq(0, 7), chWR})
	bad := chMove(chSq(0, 4), chSq(0, 6), chWK, 0x28) // castle + bit 5
	require.Empty(t, h.call(t, "move", b, bad, chApply(b, bad)))
	good := chMove(chSq(0, 4), chSq(0, 6), chWK, 0x08)
	require.NotEmpty(t, h.call(t, "move", b, good, chApply(b, good)))
}

func TestChess_Castling_BoardOK_RejectsInvalidRightsBits(t *testing.T) {
	h := loadChessScript(t)
	b := chNewStartBoard()
	b[66] = 0x10 // bit 4 — reserved
	require.Empty(t, h.call(t, "boardOK", b))
}

// =============================================================================
// Tests: pawn promotion (moveSpec[4] = promotion piece)
// =============================================================================

// chPromotionBoard returns a minimal board with white king e1, black king
// h8 (out of the way of the a-file), and one white pawn on a7 so the pawn
// can promote in one step.
func chPromotionBoard(side byte) []byte {
	b := chBoardWithKings(chSq(0, 4), chSq(7, 7)) // wK e1, bK h8
	b = chSet(b, chSq(6, 0), chWP)                // wP on a7
	b[68] = side
	return b
}

func TestChess_Promotion_WhiteToQueen(t *testing.T) {
	h := loadChessScript(t)
	b := chPromotionBoard(chWHITE)
	spec := []byte{byte(chSq(6, 0)), byte(chSq(7, 0)), chWP, 0, chWQ}
	res := chApply(b, spec)
	require.NotEmpty(t, h.call(t, "playerMove",
		[]byte{chWHITE}, b, spec, res))
	require.Equal(t, byte(chWQ), res[chSq(7, 0)],
		"a8 has the promoted queen, not the pawn")
}

func TestChess_Promotion_WhiteUnderpromotionsAllSucceed(t *testing.T) {
	h := loadChessScript(t)
	for _, p := range []byte{chWQ, chWR, chWB, chWN} {
		b := chPromotionBoard(chWHITE)
		spec := []byte{byte(chSq(6, 0)), byte(chSq(7, 0)), chWP, 0, p}
		res := chApply(b, spec)
		require.NotEmpty(t, h.call(t, "playerMove",
			[]byte{chWHITE}, b, spec, res),
			"underpromotion to %#x should succeed", p)
		require.Equal(t, p, res[chSq(7, 0)])
	}
}

func TestChess_Promotion_BlackToQueen(t *testing.T) {
	h := loadChessScript(t)
	// Mirror: black pawn on a2, black to move.
	b := chBoardWithKings(chSq(0, 7), chSq(7, 0)) // wK h1, bK a8
	b = chSet(b, chSq(1, 0), chBP)                // bP a2
	b[68] = chBLACK
	spec := []byte{byte(chSq(1, 0)), byte(chSq(0, 0)), chBP, 0, chBQ}
	res := chApply(b, spec)
	require.NotEmpty(t, h.call(t, "playerMove",
		[]byte{chBLACK}, b, spec, res))
	require.Equal(t, byte(chBQ), res[chSq(0, 0)])
}

func TestChess_Promotion_MissingPieceRejected(t *testing.T) {
	h := loadChessScript(t)
	// Pawn reaching back rank but moveSpec[4] = 0: must be rejected.
	b := chPromotionBoard(chWHITE)
	spec := []byte{byte(chSq(6, 0)), byte(chSq(7, 0)), chWP, 0, 0}
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_Promotion_KingPieceRejected(t *testing.T) {
	h := loadChessScript(t)
	// Promoting to a king (typeOf == 6) is not allowed; only Q/R/B/N.
	b := chPromotionBoard(chWHITE)
	spec := []byte{byte(chSq(6, 0)), byte(chSq(7, 0)), chWP, 0, chWK}
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_Promotion_PawnPieceRejected(t *testing.T) {
	h := loadChessScript(t)
	// Promoting to a pawn (typeOf == 1) makes no sense; rejected.
	b := chPromotionBoard(chWHITE)
	spec := []byte{byte(chSq(6, 0)), byte(chSq(7, 0)), chWP, 0, chWP}
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_Promotion_WrongColorRejected(t *testing.T) {
	h := loadChessScript(t)
	// White pawn promoting must promote to a white piece.
	b := chPromotionBoard(chWHITE)
	spec := []byte{byte(chSq(6, 0)), byte(chSq(7, 0)), chWP, 0, chBQ}
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

func TestChess_Promotion_NonPromotingMoveByteFourMustBeZero(t *testing.T) {
	h := loadChessScript(t)
	// Ordinary e2-e4 with byte 4 = chWQ: rejected (no promotion happening).
	start := chNewStartBoard()
	spec := []byte{byte(chSq(1, 4)), byte(chSq(3, 4)), chWP, 0, chWQ}
	require.Empty(t, h.call(t, "move", start, spec, chApply(start, spec)))
}

func TestChess_Promotion_NonPawnByteFourMustBeZero(t *testing.T) {
	h := loadChessScript(t)
	// Knight move with byte 4 = chWQ: not a pawn, byte 4 must be 0.
	b := chBoardWithKings(chSq(0, 4), chSq(7, 0))
	b = chSet(b, chSq(0, 6), chWN)
	spec := []byte{byte(chSq(0, 6)), byte(chSq(2, 5)), chWN, 0, chWQ}
	require.Empty(t, h.call(t, "move", b, spec, chApply(b, spec)))
}

// =============================================================================
// Tests: en passant
// =============================================================================

func TestChess_EP_TargetSetAfterTwoSquarePush(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	spec := chMove(chSq(1, 4), chSq(3, 4), chWP, 0) // e2-e4
	res := chApply(start, spec)
	require.NotEmpty(t, h.call(t, "move", start, spec, res))
	require.Equal(t, byte(chSq(2, 4)), res[67],
		"EP target = e3 (midpoint of e2-e4)")
}

func TestChess_EP_TargetClearedAfterOtherMoves(t *testing.T) {
	h := loadChessScript(t)
	// After a 2-square push by white, EP target = e3. Then black makes a
	// non-EP move; EP target must clear back to 0xff.
	start := chNewStartBoard()
	push := chMove(chSq(1, 4), chSq(3, 4), chWP, 0) // 1. e4
	mid := chApply(start, push)
	require.NotEmpty(t, h.call(t, "move", start, push, mid))

	// 1...Nc6 (no double push, EP must clear).
	reply := chMove(chSq(7, 1), chSq(5, 2), chBN, 0)
	res := chApply(mid, reply)
	require.NotEmpty(t, h.call(t, "move", mid, reply, res))
	require.Equal(t, byte(chEPNone), res[67])
}

func TestChess_EP_WhiteCapturesBlack(t *testing.T) {
	h := loadChessScript(t)
	// Set up: white pawn on d5, black pawn on e7. Black plays e7-e5,
	// which sets EP target = e6. White then EP-captures via dxe6.
	b := chBoardWithKings(chSq(0, 4), chSq(7, 4)) // wK e1, bK e8
	b = chSet(b, chSq(4, 3), chWP)                // wP d5
	b = chSet(b, chSq(6, 4), chBP)                // bP e7
	b[68] = chBLACK
	push := chMove(chSq(6, 4), chSq(4, 4), chBP, 0) // ...e5
	afterPush := chApply(b, push)
	require.NotEmpty(t, h.call(t, "move", b, push, afterPush))
	require.Equal(t, byte(chSq(5, 4)), afterPush[67],
		"EP target = e6 after black's 2-square push")

	// White now EP-captures: pawn d5 -> e6, capture flag + EP flag.
	cap := chMove(chSq(4, 3), chSq(5, 4), chWP, chFlagCapture|chFlagEP)
	res := chApply(afterPush, cap)
	require.NotEmpty(t, h.call(t, "playerMove",
		[]byte{chWHITE}, afterPush, cap, res),
		"white can capture en passant on e6")
	require.Equal(t, byte(chWP), res[chSq(5, 4)], "white pawn now on e6")
	require.Equal(t, byte(chEMPTY), res[chSq(4, 4)], "black pawn captured (e5 cleared)")
	require.Equal(t, byte(chEMPTY), res[chSq(4, 3)], "white's d5 cleared")
	require.Equal(t, byte(chEPNone), res[67], "EP cleared after EP capture")
}

func TestChess_EP_BlackCapturesWhite(t *testing.T) {
	h := loadChessScript(t)
	// White pushes e2-e4 with a black pawn on d4 ready to EP-capture.
	b := chBoardWithKings(chSq(0, 0), chSq(7, 4)) // wK a1, bK e8
	b = chSet(b, chSq(1, 4), chWP)                // wP e2
	b = chSet(b, chSq(3, 3), chBP)                // bP d4
	push := chMove(chSq(1, 4), chSq(3, 4), chWP, 0)
	afterPush := chApply(b, push)
	require.NotEmpty(t, h.call(t, "move", b, push, afterPush))
	require.Equal(t, byte(chSq(2, 4)), afterPush[67])

	cap := chMove(chSq(3, 3), chSq(2, 4), chBP, chFlagCapture|chFlagEP)
	res := chApply(afterPush, cap)
	require.NotEmpty(t, h.call(t, "playerMove",
		[]byte{chBLACK}, afterPush, cap, res))
	require.Equal(t, byte(chBP), res[chSq(2, 4)])
	require.Equal(t, byte(chEMPTY), res[chSq(3, 4)], "white pawn at e4 captured")
}

func TestChess_EP_StaleTargetRejected(t *testing.T) {
	h := loadChessScript(t)
	// EP capture is only legal on the move IMMEDIATELY following the
	// 2-square push. After any intermediate move, EP must clear and the
	// would-be EP capture must be rejected.
	b := chBoardWithKings(chSq(0, 4), chSq(7, 4))
	b = chSet(b, chSq(4, 3), chWP)
	b = chSet(b, chSq(6, 4), chBP)
	b[68] = chBLACK
	// 1...e5
	push := chMove(chSq(6, 4), chSq(4, 4), chBP, 0)
	afterPush := chApply(b, push)
	require.NotEmpty(t, h.call(t, "move", b, push, afterPush))
	// 2. Kf1 (white waiver — non-EP move). EP target clears.
	wait := chMove(chSq(0, 4), chSq(0, 5), chWK, 0)
	afterWait := chApply(afterPush, wait)
	require.NotEmpty(t, h.call(t, "move", afterPush, wait, afterWait))
	require.Equal(t, byte(chEPNone), afterWait[67])
	// 2...Kd8 (any black move using a piece that's actually on the board).
	// EP target stays cleared.
	bm := chMove(chSq(7, 4), chSq(7, 3), chBK, 0)
	afterBlack := chApply(afterWait, bm)
	require.NotEmpty(t, h.call(t, "move", afterWait, bm, afterBlack))
	// 3. dxe6 attempted: must be rejected (EP target is 0xff now).
	stale := chMove(chSq(4, 3), chSq(5, 4), chWP, chFlagCapture|chFlagEP)
	require.Empty(t, h.call(t, "move", afterBlack, stale, chApply(afterBlack, stale)))
}

func TestChess_EP_TargetNonEmptyRejected(t *testing.T) {
	h := loadChessScript(t)
	// EP destination must be empty in start. If something occupies the EP
	// target square, the EP capture is wrong.
	b := chBoardWithKings(chSq(0, 0), chSq(7, 4))
	b = chSet(b, chSq(4, 3), chWP)
	b = chSet(b, chSq(4, 4), chBP) // black pawn at e5 (the would-be captured)
	b = chSet(b, chSq(5, 4), chBN) // something already on e6
	b[67] = byte(chSq(5, 4))       // claim EP available at e6
	cap := chMove(chSq(4, 3), chSq(5, 4), chWP, chFlagCapture|chFlagEP)
	require.Empty(t, h.call(t, "move", b, cap, chApply(b, cap)))
}

// =============================================================================
// Tests: side-to-move
// =============================================================================

func TestChess_SideToMove_StartIsWhite(t *testing.T) {
	h := loadChessScript(t)
	got := h.call(t, "sideToMove", chNewStartBoard())
	require.Equal(t, []byte{chWHITE}, got)
}

func TestChess_SideToMove_FlipsAfterMove(t *testing.T) {
	h := loadChessScript(t)
	start := chNewStartBoard()
	spec := chMove(chSq(1, 4), chSq(3, 4), chWP, 0)
	res := chApply(start, spec)
	require.NotEmpty(t, h.call(t, "move", start, spec, res),
		"move accepts the result with byte 68 flipped")
	got := h.call(t, "sideToMove", res)
	require.Equal(t, []byte{chBLACK}, got)
}

func TestChess_SideToMove_NoFlipIsRejected(t *testing.T) {
	h := loadChessScript(t)
	// Start board says white moves; result with byte 68 still white must
	// be rejected by sideTransOK inside move.
	start := chNewStartBoard()
	spec := chMove(chSq(1, 4), chSq(3, 4), chWP, 0)
	res := chApply(start, spec)
	res[68] = chWHITE // tamper: side did not flip
	require.Empty(t, h.call(t, "move", start, spec, res))
}

func TestChess_PlayerMove_RejectsWhenNotPlayersTurn(t *testing.T) {
	h := loadChessScript(t)
	// Start is white-to-move; black tries to call playerMove(BLACK,...).
	start := chNewStartBoard()
	spec := chMove(chSq(6, 4), chSq(4, 4), chBP, 0)
	require.Empty(t, h.call(t, "playerMove",
		[]byte{chBLACK}, start, spec, chApply(start, spec)),
		"black cannot move when byte(start, 68) == white")
}

func TestChess_BoardOK_RejectsInvalidEPByte(t *testing.T) {
	h := loadChessScript(t)
	b := chNewStartBoard()
	b[67] = 64 // out of 0..63 and not 0xff
	require.Empty(t, h.call(t, "boardOK", b))
}

func TestChess_BoardOK_RejectsInvalidSideByte(t *testing.T) {
	h := loadChessScript(t)
	b := chNewStartBoard()
	b[68] = 0x30 // not white (0x10) or black (0x20)
	require.Empty(t, h.call(t, "boardOK", b))
}
