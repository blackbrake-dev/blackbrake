// Opt-in reports to the blackbrake team (F6.8 fills this in; the pure core is src/report/, F6.7).
// For now: the registered shape, and an honest "not available yet" that changes nothing.
import { t } from '../../i18n.mjs';

const unavailable = (ctx) => {
  ctx.print(['', `  ${ctx.p.amber(t('Reports are not available yet.'))}`, '']);

  return 1;
};

export default {
  id: 'report',
  commands: [
    { name: 'report', usage: 'blackbrake report [product|security]', help: () => t('prepare a report; nothing is sent'), args: 3, run: unavailable },
  ],
  menu: [
    {
      slot: 'more',
      order: 65,
      value: 'report-product',
      label: () => t('Send feedback or report a problem…'),
      hint: () => t('prepare a message for hello@blackbrake.dev; nothing is sent'),
      run: (ctx) => { unavailable(ctx); },
    },
    {
      slot: 'more',
      order: 66,
      value: 'report-security',
      label: () => t('Report a security issue…'),
      hint: () => t('prepare a message for security@blackbrake.dev; nothing is sent'),
      run: (ctx) => { unavailable(ctx); },
    },
  ],
};
