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

func chNewStartBoard() []byte {
	b := make([]byte, 64)
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
	return b
}

func chEmptyBoard() []byte { return make([]byte, 64) }

func chSet(b []byte, sq int, piece byte) []byte {
	out := make([]byte, 64)
	copy(out, b)
	out[sq] = piece
	return out
}

func chMove(from, to int, piece, flags byte) []byte {
	return []byte{byte(from), byte(to), piece, flags, 0}
}

// chApply produces the result-board obtained by applying spec to start.
// Used to build the "expected result" for valid-move tests.
func chApply(start, spec []byte) []byte {
	out := make([]byte, 64)
	copy(out, start)
	out[spec[0]] = chEMPTY
	out[spec[1]] = spec[2]
	return out
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
	t.Logf("chess script bytecode size: %d", len(bin))
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
	require.Empty(t, h.call(t, "isStart", chNewStartBoard()[:63]))
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
	require.Empty(t, h.call(t, "move", start[:63], spec, good))
	// Wrong result length.
	require.Empty(t, h.call(t, "move", start, spec, good[:63]))
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
	spec := chMove(chSq(1, 4), chSq(3, 4), chWP, 0x10) // high bit
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
