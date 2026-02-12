import { fn, BigInt } from 'download0/types'

// Cached JB status — avoids repeated getuid()+setuid() syscalls (PR #67 idea)
let _jbCached: boolean | null = null

export function checkJailbroken (): boolean {
  // Return cached result if available (safe — JB status doesn't change within a session)
  if (_jbCached !== null) return _jbCached

  fn.register(24, 'getuid', [], 'bigint')
  fn.register(23, 'setuid', ['number'], 'bigint')

  const uidBefore = fn.getuid()
  const uidBeforeVal = uidBefore instanceof BigInt ? uidBefore.lo : uidBefore
  log('UID before setuid: ' + uidBeforeVal)

  log('Attempting setuid(0)...')

  try {
    const setuidResult = fn.setuid(0)
    const setuidRet = setuidResult instanceof BigInt ? setuidResult.lo : setuidResult
    log('setuid returned: ' + setuidRet)
  } catch (e) {
    log('setuid threw exception: ' + (e as Error).toString())
  }

  const uidAfter = fn.getuid()
  const uidAfterVal = uidAfter instanceof BigInt ? uidAfter.lo : uidAfter
  log('UID after setuid: ' + uidAfterVal)

  const jailbroken = uidAfterVal === 0
  log(jailbroken ? 'Already jailbroken' : 'Not jailbroken')
  _jbCached = jailbroken
  return jailbroken
}

export function resetJBCache (): void {
  _jbCached = null
}
