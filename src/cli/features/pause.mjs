// Pause / resume all of blackbrake (F6.4 fills this in). For now: the registered shape, and an
// honest "not available yet" that changes nothing.
import { t } from '../../i18n.mjs';

const unavailable = (ctx, text) => {
  ctx.print(['', `  ${ctx.p.amber(text)}`, '']);

  return 1;
};

export default {
  id: 'pause',
  commands: [
    { name: 'pause', usage: 'blackbrake pause', help: () => t('pause everything; nothing is uninstalled'), run: (ctx) => unavailable(ctx, t('Pausing is not available yet.')) },
    { name: 'resume', usage: 'blackbrake resume', help: () => t('resume after a pause'), run: (ctx) => unavailable(ctx, t('Resuming is not available yet.')) },
  ],
  menu: [
    {
      slot: 'main',
      order: 35,
      value: 'pause',
      label: () => t('Pause all of blackbrake'),
      hint: () => t('stops watching and protecting until you resume; nothing is uninstalled'),
      run: (ctx) => { unavailable(ctx, t('Pausing is not available yet.')); },
    },
  ],
};
