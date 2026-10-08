import { describe, expect, it } from 'vitest';
import { parseEml } from '../src/engine/email/emlParser';
import { MAX_EML_SIZE } from '../src/engine/email/headerVerifier';

describe('parseEml', () => {
  it('extracts selected headers, plain text, and unverified auth alignment claims', async () => {
    const email = await parseEml([
      'From: "Example Support" <help@example.com>',
      'To: user@example.net',
      'Cc: audit@example.net',
      'Reply-To: help@example.com',
      'Return-Path: <bounce@example.com>',
      'Subject: Account notice',
      'Date: Tue, 1 Oct 2026 10:00:00 +0000',
      'Message-ID: <id@example.com>',
      'Received: from mx.example.com',
      'Authentication-Results: mx.receiver; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com',
      'DKIM-Signature: v=1; d=example.com',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'Visit https://example.com/account',
    ].join('\r\n'));

    expect(email.headers.map(({ name }) => name)).toEqual([
      'from', 'to', 'cc', 'reply-to', 'return-path', 'subject', 'date', 'message-id',
      'received', 'authentication-results', 'dkim-signature',
    ]);
    expect(email.plainText).toContain('Visit https://example.com/account');
    expect(email.links).toContainEqual({
      url: 'https://example.com/account',
      source: 'body',
    });
    expect(email.headerAssessment.alignment).toEqual({
      spf: 'aligned',
      dkim: 'aligned',
      dmarc: 'aligned',
    });
  });

  it('hashes attachment bytes without opening or executing the attachment', async () => {
    const email = await parseEml([
      'From: sender@example.com',
      'Subject: attachment',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="mime-test"',
      '',
      '--mime-test',
      'Content-Type: text/plain; charset=utf-8',
      '',
      'The attachment is included.',
      '--mime-test',
      'Content-Type: application/pdf; name="sample.pdf"',
      'Content-Disposition: attachment; filename="sample.pdf"',
      'Content-Transfer-Encoding: base64',
      '',
      'UERGREFUQQ==',
      '--mime-test--',
      '',
    ].join('\r\n'));

    expect(email.plainText).toContain('The attachment is included.');
    expect(email.attachments).toHaveLength(1);
    expect(email.attachments[0]).toMatchObject({
      filename: 'sample.pdf',
      extension: 'pdf',
      mimeType: 'application/pdf',
      size: 7,
    });
    expect(email.attachments[0].sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it('rejects malformed transfer encodings and invalid header input', async () => {
    await expect(parseEml('not an email')).rejects.toThrow('No valid email headers');
    await expect(parseEml([
      'From: sender@example.com',
      'Content-Type: application/octet-stream',
      'Content-Transfer-Encoding: base64',
      '',
      'not base64!',
    ].join('\n'))).rejects.toThrow('invalid base64');
  });

  it('rejects messages above the total byte limit before parsing MIME content', async () => {
    await expect(parseEml(`From: sender@example.com\n\n${'x'.repeat(MAX_EML_SIZE)}`))
      .rejects.toThrow('bytes or fewer');
    await expect(parseEml(`From: sender@example.com\n\n${'é'.repeat(MAX_EML_SIZE / 2)}`))
      .rejects.toThrow('bytes or fewer');
  });
});
