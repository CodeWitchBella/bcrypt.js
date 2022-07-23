/**
 * Continues with the callback on the next tick.
 * @function
 * @param {function(...[*])} callback Callback to execute
 * @inner
 */
export function nextTick(cb) {
    Promise.resolve().then(cb)
}
