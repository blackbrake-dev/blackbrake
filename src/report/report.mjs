// Report assistant: list, show, check, send, delete subcommands with proper dispatch.
// F6.8 deliverable: menu integration, TTY checks, validation, aggregate persistence.
import { t } from '../i18n.mjs';
import { listReports, readReportStore, validateReportPath } from './store.mjs';
import { reportMenu, persistReport, openReport, sendReportViaMailto } from './open.mjs';
import { validateReport, isReportFileName } from './validate.mjs';
import { auditAggregates, persistAggregates, loadAggregate } from './persist.mjs';
import fs from 'node:fs';
import path from 'node:path';

export const REPORT_COMMANDS = {
  list: {
    name: 'report list',
    help: () => t('list local reports'),
    usage: 'blackbrake report list',
    run: async (ctx) => {
      const { home } = ctx;
      const reports = listReports(home);

      if (reports.length === 0) {
        ctx.print([t('No reports yet.')]);
        return 0;
      }

      ctx.print(['', t('Local reports:'), '']);
      for (const name of reports) {
        ctx.print([`  ${name}`]);
      }
      ctx.print(['']);
      return 0;
    },
  },

  show: {
    name: 'report show',
    help: () => t('read a local report'),
    usage: 'blackbrake report show <name>',
    run: async (ctx) => {
      const [name] = ctx.opts.rest;

      if (!name || !isReportFileName(name)) {
        ctx.print([t('Usage: blackbrake report show <name>')]);
        return 1;
      }

      const { home } = ctx;
      const filePath = path.join(home, '.blackbrake', 'reports', name);
      const validated = validateReportPath(filePath, home);

      if (!validated.ok) {
        ctx.print([t('Report not found.')]);
        return 1;
      }

      try {
        const content = fs.readFileSync(filePath, 'utf8');
        ctx.print(['', content, '']);
        return 0;
      } catch (e) {
        ctx.print([t('Cannot read report.')]);
        return 1;
      }
    },
  },

  check: {
    name: 'report check',
    help: () => t('validate a report file'),
    usage: 'blackbrake report check <path>',
    run: async (ctx) => {
      const [reportPath] = ctx.opts.rest;

      if (!reportPath) {
        ctx.print([t('Usage: blackbrake report check <path>')]);
        return 1;
      }

      try {
        const content = fs.readFileSync(reportPath, 'utf8');
        const validated = validateReport(content);

        if (!validated.ok) {
          ctx.print([t('Report has {n} problems:', { n: validated.problems.length }), '']);
          for (const p of validated.problems.slice(0, 5)) {
            const code = p.code || p.rule;
            ctx.print([`  Line ${p.line}: ${code}`]);
          }
          if (validated.problems.length > 5) {
            ctx.print([`  … and ${validated.problems.length - 5} more`]);
          }
          return 1;
        }

        ctx.print([t('Report is valid.')]);
        return 0;
      } catch (e) {
        ctx.print([t('Cannot read file.')]);
        return 1;
      }
    },
  },

  send: {
    name: 'report send',
    help: () => t('prepare to send a report'),
    usage: 'blackbrake report send <kind> <name>',
    run: async (ctx) => {
      const [kind, name] = ctx.opts.rest;

      if (!kind || !['product', 'security'].includes(kind) || !name || !isReportFileName(name)) {
        ctx.print([t('Usage: blackbrake report send (product|security) <name>')]);
        return 1;
      }

      const { home } = ctx;
      const filePath = path.join(home, '.blackbrake', 'reports', name);
      const validated = validateReportPath(filePath, home);

      if (!validated.ok) {
        ctx.print([t('Report not found.')]);
        return 1;
      }

      try {
        const content = fs.readFileSync(filePath, 'utf8');

        const email = kind === 'product' ? 'hello@blackbrake.dev' : 'security@blackbrake.dev';
        const subject = `blackbrake ${kind} report`;

        // Prepare mailto
        const result = sendReportViaMailto(email, subject, content);

        if (result.ok) {
          ctx.print([t('Report prepared. Your mail client should open.'), '']);
          return 0;
        } else {
          ctx.print([t('Could not open mail client.')]);
          return 1;
        }
      } catch (e) {
        ctx.print([t('Cannot prepare report.')]);
        return 1;
      }
    },
  },

  delete: {
    name: 'report delete',
    help: () => t('delete a local report'),
    usage: 'blackbrake report delete <name>',
    run: async (ctx) => {
      const [name] = ctx.opts.rest;

      if (!name || !isReportFileName(name)) {
        ctx.print([t('Usage: blackbrake report delete <name>')]);
        return 1;
      }

      const { home } = ctx;
      const filePath = path.join(home, '.blackbrake', 'reports', name);
      const validated = validateReportPath(filePath, home);

      if (!validated.ok) {
        ctx.print([t('Report not found.')]);
        return 1;
      }

      try {
        fs.unlinkSync(filePath);
        ctx.print([t('Report deleted.')]);
        return 0;
      } catch (e) {
        ctx.print([t('Cannot delete report.')]);
        return 1;
      }
    },
  },
};

export async function runReport(ctx) {
  const [subcommand] = ctx.opts.rest;

  if (!subcommand || !REPORT_COMMANDS[subcommand]) {
    ctx.print([t('Usage: blackbrake report (list|show|check|send|delete) [args]')]);
    return 1;
  }

  const cmd = REPORT_COMMANDS[subcommand];
  return cmd.run(ctx) || 0;
}
