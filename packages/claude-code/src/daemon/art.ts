// Inline Rubric mark for the Claude Code permission prompt (shown on `ask`
// and `deny`): a small boxed badge — an orange square + the wordmark inside
// a thin box. The hook reason is static text rendered once (no
// animation/throb is possible), so this is the whole mark.
//
// The orange square is a background-painted space (always one column) so the
// box borders stay aligned in any terminal. Magma orange is #FF5A1F (the web
// UI's --accent token); terminals without truecolour render an empty square.

const ORANGE_FG = '\x1b[38;2;255;90;31m';
const RESET = '\x1b[0m';
// A square glyph (not a full-cell background fill, which reads as a tall
// rectangle) painted in magma orange.
const SQUARE = `${ORANGE_FG}■${RESET}`;

/** Inline Rubric mark: an orange square + "Rubric" inside a thin box. */
export function rubricMark(): string {
  return ['┌──────────┐', `│ ${SQUARE} Rubric │`, '└──────────┘'].join('\n');
}
