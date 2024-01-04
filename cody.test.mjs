import test from 'node:test';
import assert from 'node:assert';

import { app, server } from './index.mjs';


test('middleware', async (t) => {

  await t.test('blocks blocked domains', async (t) => {
    const req = {
      headers: {
        host: 'blocked.com'
      }
    };

    const res = {
      status: () => {},
      send: () => {}
    };

    const next = () => {};

    await (req, res, next);

    assert(res.status.calledWith(403));
    assert(res.send.calledWith('Remote delivery blocked'));
    assert(next.calledOnce);
  });

  await t.test('allows non-blocked domains', async (t) => {
    const req = {
      headers: {
        host: 'allowed.com' 
      }
    };
    
    const next = () => {};

    await middleware(req, {}, next);
    
    assert(next.calledOnce);
  });

});
