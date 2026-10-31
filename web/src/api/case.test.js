import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createCase, watchJob } from './case.js'
import { resetSession, session } from '../store/session.js'

test('a case is created from the file when both are given, otherwise from the text', async () => {
  const sent = []
  globalThis.fetch = async (_, init) => { sent.push(init.body); return Response.json({ id: 'x' }) }
  await createCase(new File(['a'], 'a.txt'), 'pasted')
  await createCase(null, 'pasted')
  assert.deepEqual([...sent[0].keys()], ['file'])
  assert.deepEqual([...sent[1].keys()], ['text'])
  assert.equal(sent[1].get('text'), 'pasted')
})

test('a poll still in flight when the case changes is dropped', async () => {
  let reply
  globalThis.fetch = () => new Promise((resolve) => { reply = resolve })
  watchJob('old')
  resetSession()
  reply(Response.json({ id: 'old', display_name: 'old.pdf', status: 'running', stages: [], findings: [] }))
  await new Promise((resolve) => setTimeout(resolve, 10))
  assert.equal(session.job, null)
  assert.equal(session.filename, '')
})
