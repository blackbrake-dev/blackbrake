// Where the 0.3.x features plug into the menu, the dispatcher and the help, so that adding one
// does not mean editing bin/blackbrake.mjs or src/ui/home.mjs.
//
// A feature is a module in src/cli/features/ whose default export looks like this:
//
//   export default {
//     id: 'pause',
//     commands: [{
//       name: 'pause',                       // `blackbrake pause`; built-in commands win over these
//       usage: 'blackbrake pause',           // shown in the help; starts with "blackbrake <name>"
//       help: () => t(<literal text>),       // a literal inside t(): the i18n test wants its Spanish text
//       args: 0,                             // how many positional words it accepts (default 0)
//       run: async (ctx) => 0,               // resolves to the exit code (nothing = 0)
//     }],
//     menu: [{
//       slot: 'main',                        // 'main' or a group: live | audit | protect | more
//       order: 35,                           // built-in rows are 10, 20, 30…; "Close this menu" and "Back" stay last
//       value: 'pause',                      // the action; must not collide with a built-in one
//       label: (state) => t(<literal text>),
//       hint: (state) => t(<literal text>),  // optional
//       tag: (state, p) => '…',              // optional, a ready-made coloured string (rawTag)
//       disabled: (state) => false,          // optional
//       run: async (ctx) => undefined,       // { exit: true } ends the interactive session
//     }],
//   };
//
// `ctx` is { p, opts, print, pkg, state }: the painter, the parsed arguments (opts.rest holds the
// positional words), print(lines), package.json, and (for menu rows) the state the menu was drawn
// with. Spanish text goes in src/i18n/es-<name>.mjs (`export const ES = { 'English': 'Español' }`,
// optionally `ES_PATTERNS`); src/i18n-es.mjs merges those files by itself.
import pause from './features/pause.mjs';
import report from './features/report.mjs';
import uninstallMenu from './features/uninstall-menu.mjs';

export const FEATURES = [pause, uninstallMenu, report];

const commands = () => FEATURES.flatMap((f) => (f.commands ?? []).map((c) => ({ ...c, feature: f.id })));

const rows = () => FEATURES.flatMap((f) => (f.menu ?? []).map((r) => ({ ...r, feature: f.id })));

export const commandFor = (name) => commands().find((c) => c.name === name);

// How many positional words a registered command takes (the parser needs it before dispatching).
export const commandArgs = (name) => commandFor(name)?.args ?? 0;

// Rows of one slot, in order.
export const menuRows = (slot) => rows().filter((r) => r.slot === slot).sort((a, b) => a.order - b.order);

export const findMenuRow = (value) => rows().find((r) => r.value === value);

// Rows of a slot as menu items (see src/ui/menu.mjs), each with the order it asks for.
export const menuItems = (slot, state = {}, p = null) => menuRows(slot).map((r) => {
  const item = { value: r.value, label: r.label(state) };

  if (r.hint) item.hint = r.hint(state);

  if (r.tag && p) {
    item.tag = r.tag(state, p);
    item.rawTag = true;
  }

  if (r.disabled?.(state)) item.disabled = true;

  return { order: r.order, item };
});

// One line per registered command, for the help: { usage, text } with the text already translated.
export const helpRows = () => commands().filter((c) => c.usage && c.help).map((c) => ({ usage: c.usage, text: c.help() }));
