import nodemailer, { type Transporter } from 'nodemailer';

let transport: Transporter | undefined;

function getTransport() {
  transport ??= nodemailer.createTransport({
    host: process.env.SMTP_HOST ?? 'localhost',
    port: Number(process.env.SMTP_PORT ?? 1025),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
  return transport;
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export async function sendMail(to: string, subject: string, intro: string, cta: { label: string; url: string }) {
  const html = `<div style="font-family:system-ui,sans-serif;max-width:480px;margin:auto;padding:24px">
<h2 style="color:#4f46e5;margin:0 0 16px">depguard</h2>
<p>${esc(intro)}</p>
<p><a href="${esc(cta.url)}" style="display:inline-block;background:#4f46e5;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none">${esc(cta.label)}</a></p>
<p style="color:#666;font-size:12px">If the button does not work, paste this link into your browser:<br>${esc(cta.url)}</p>
</div>`;
  await getTransport().sendMail({
    from: process.env.SMTP_FROM ?? 'depguard <no-reply@depguard.local>',
    to,
    subject,
    text: `${intro}\n\n${cta.label}: ${cta.url}\n`,
    html,
  });
}
