import { describe, expect, it } from 'vitest';
import { addAllowOnce, consumeAllowOnce, type SessionStore } from '../src/background/allowOnce';

function createStore(): SessionStore {
  const values: Record<string, unknown> = {};
  return {
    async get(key) {
      return { [key]: values[key] };
    },
    async set(items) {
      Object.assign(values, items);
    },
    async remove(key) {
      delete values[key];
    },
  };
}

describe('allow once approvals', () => {
  it('allows only the approved URL once, not later visits to the same host', async () => {
    const store = createStore();
    expect(await addAllowOnce('https://example.com/login#form', store)).toBe(true);

    expect(await consumeAllowOnce('https://example.com/login', store)).toBe(true);
    expect(await consumeAllowOnce('https://example.com/login', store)).toBe(false);
    expect(await consumeAllowOnce('https://example.com/account', store)).toBe(false);
  });

  it('rejects non-web destinations', async () => {
    const store = createStore();
    expect(await addAllowOnce('javascript:alert(1)', store)).toBe(false);
    expect(await consumeAllowOnce('javascript:alert(1)', store)).toBe(false);
  });
});