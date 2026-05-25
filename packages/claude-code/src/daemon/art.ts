// Terminal art for the Rubric mark, shown in the Claude Code permission
// prompt on `ask` and `deny`. The mark mirrors the product logo: a 3x3
// grid with the centre cell filled in Rubric orange (#F94B0E).
//
// Colour is emitted as a 24-bit ANSI escape. Terminals that don't honour
// it simply render the cell as the plain block glyph — alignment is
// unaffected because the escape sequences occupy zero display columns.

// Rubric brand orange, as a 24-bit ANSI foreground escape.
const ORANGE = '\x1b[38;2;249;75;14m';
const RESET = '\x1b[0m';

/** The orange centre block, wrapped so it renders in brand colour where supported. */
const CENTER = `${ORANGE}███${RESET}`;

/**
 * The Rubric mark: a square 3x3 grid with an orange centre cell and the
 * wordmark beside it. Cells are three columns wide with blank rows between
 * the dividers so the grid reads square (terminal cells are ~2:1 tall).
 */
export function rubricMark(): string {
  return [
    '┌───┬───┬───┐',
    '│   │   │   │',
    '├───┼───┼───┤',
    `│   │${CENTER}│   │   R U B R I C`,
    '├───┼───┼───┤',
    '│   │   │   │',
    '└───┴───┴───┘',
  ].join('\n');
}
