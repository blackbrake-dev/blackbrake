// "Uninstall blackbrake…" in the main menu (F6.3 fills this in). The `blackbrake uninstall`
// command stays a built-in of bin/blackbrake.mjs. For now: the row, and an honest "not available
// yet" that changes nothing.
import { t } from '../../i18n.mjs';

export default {
  id: 'uninstall-menu',
  commands: [],
  menu: [
    {
      slot: 'main',
      order: 50,
      value: 'uninstall',
      label: () => t('Uninstall blackbrake…'),
      hint: () => t('remove it from every agent and stop everything'),
      run: (ctx) => { ctx.print(['', `  ${ctx.p.amber(t('The uninstall menu is not available yet. In a terminal of your own, "blackbrake uninstall" still works.'))}`, '']); },
    },
  ],
};
