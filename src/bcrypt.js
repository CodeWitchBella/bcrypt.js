import { nextTick } from './bcrypt/util.js'
import { base64_encode, base64_decode } from './bcrypt/util/base64.js'
import { BCRYPT_SALT_LEN, GENSALT_DEFAULT_LOG2_ROUNDS, _hash } from './bcrypt/impl.js'

let crypto

export function setCrypto(c) {
    crypto = c
}

/**
 * Generates cryptographically secure random bytes.
 * @function
 * @param {number} len Bytes length
 * @returns {!Array.<number>} Random bytes
 * @throws {Error} If no random implementation is available
 * @inner
 */
function random(len) {
    const a = new Uint32Array(len);
    (crypto || globalThis.crypto).getRandomValues(a);
    return Array.prototype.slice.call(a);
}

/**
 * Synchronously generates a salt.
 * @param {number=} rounds Number of rounds to use, defaults to 10 if omitted
 * @returns {string} Resulting salt
 * @throws {Error} If a random fallback is required but not set
 */
export function genSaltSync(rounds) {
    rounds = rounds || GENSALT_DEFAULT_LOG2_ROUNDS;
    if (typeof rounds !== 'number')
        throw Error("Illegal arguments: "+(typeof rounds));
    if (rounds < 4)
        rounds = 4;
    else if (rounds > 31)
        rounds = 31;
    var salt = [];
    salt.push("$2a$");
    if (rounds < 10)
        salt.push("0");
    salt.push(rounds.toString());
    salt.push('$');
    salt.push(base64_encode(random(BCRYPT_SALT_LEN), BCRYPT_SALT_LEN)); // May throw
    return salt.join('');
};

/**
 * Asynchronously generates a salt.
 * @param {(number|undefined)=} rounds Number of rounds to use, defaults to 10 if omitted
 * @returns {Promise}
 * @throws {Error}
 */
export function genSalt(rounds = GENSALT_DEFAULT_LOG2_ROUNDS) {
    if (typeof rounds !== 'number')
        throw Error("illegal arguments: "+(typeof rounds));

    return Promise.resolve().then(() => {
        // Pretty thin, but salting is fast enough
        return genSaltSync(rounds)
    })
};

/**
 * Synchronously generates a hash for the given string.
 * @param {string} s String to hash
 * @param {(number|string)=} salt Salt length to generate or salt to use, default to 10
 * @returns {string} Resulting hash
 */
export function hashSync(s, salt) {
    if (typeof salt === 'undefined')
        salt = GENSALT_DEFAULT_LOG2_ROUNDS;
    if (typeof salt === 'number')
        salt = genSaltSync(salt);
    if (typeof s !== 'string' || typeof salt !== 'string')
        throw Error("Illegal arguments: "+(typeof s)+', '+(typeof salt));
    return _hash(s, salt);
};

function hashAsync(s, salt) {
    return new Promise((resolve, reject) => {
        _hash(s, salt, (err, result) => err ? reject(err) : resolve(result))
    })
}

/**
 * Asynchronously generates a hash for the given string.
 * @param {string} s String to hash
 * @param {number|string} salt Salt length to generate or salt to use
 * @returns {Promise}
 * @throws {Error}
 */
export async function hash(s, salt) {
    if (typeof s === 'string' && (typeof salt === 'number' || salt === undefined)) {
        const generatedSalt = await genSalt(salt)
        return hashAsync(s, generatedSalt)
    } else if (typeof s === 'string' && typeof salt === 'string') {
        return hashAsync(s, salt);
    } else {
        throw new Error("Illegal arguments: "+(typeof s)+', '+(typeof salt))
    }
};

/**
 * Compares two strings of the same length in constant time.
 * @param {string} known Must be of the correct length
 * @param {string} unknown Must be the same length as `known`
 * @returns {boolean}
 * @inner
 */
function safeStringCompare(known, unknown) {
    var diff = known.length ^ unknown.length;
    for (var i = 0; i < known.length; ++i) {
        diff |= known.charCodeAt(i) ^ unknown.charCodeAt(i);
    }
    return diff === 0;
}

/**
 * Synchronously tests a string against a hash.
 * @param {string} s String to compare
 * @param {string} hashParam Hash to test against
 * @returns {boolean} true if matching, otherwise false
 * @throws {Error} If an argument is illegal
 */
export function compareSync(s, hashParam) {
    if (typeof s !== "string" || typeof hashParam !== "string")
        throw Error("Illegal arguments: "+(typeof s)+', '+(typeof hashParam));
    if (hashParam.length !== 60)
        return false;
    return safeStringCompare(hashSync(s, hashParam.substr(0, hashParam.length-31)), hashParam);
};

/**
 * Asynchronously compares the given data against the given hash.
 * @param {string} s Data to compare
 * @param {string} hashParam Data to be compared to
 * @returns {Promise}
 * @throws {Error}
 */
export async function compare(s, hashParam) {
    if (typeof s !== "string" || typeof hashParam !== "string") {
        throw new Error("Illegal arguments: "+(typeof s)+', '+(typeof hashParam));
    }
    if (hashParam.length !== 60) {
        return false;
    }
    const comp = await hash(s, hashParam.substr(0, 29));
    return safeStringCompare(comp, hashParam);
};

/**
 * Gets the number of rounds used to encrypt the specified hash.
 * @param {string} hashParam Hash to extract the used number of rounds from
 * @returns {number} Number of rounds used
 * @throws {Error} If `hash` is not a string
 */
export function getRounds(hashParam) {
    if (typeof hashParam !== "string")
        throw Error("Illegal arguments: "+(typeof hashParam));
    return parseInt(hashParam.split("$")[2], 10);
};

/**
 * Gets the salt portion from a hash. Does not validate the hash.
 * @param {string} hash Hash to extract the salt from
 * @returns {string} Extracted salt part
 * @throws {Error} If `hash` is not a string or otherwise invalid
 */
export function getSalt(hash) {
    if (typeof hash !== 'string')
        throw Error("Illegal arguments: "+(typeof hash));
    if (hash.length !== 60)
        throw Error("Illegal hash length: "+hash.length+" != 60");
    return hash.substring(0, 29);
};

/**
 * Encodes a byte array to base64 with up to len bytes of input, using the custom bcrypt alphabet.
 * @function
 * @param {!Array.<number>} b Byte array
 * @param {number} len Maximum input length
 * @returns {string}
 */
export const encodeBase64 = base64_encode;

/**
 * Decodes a base64 encoded string to up to len bytes of output, using the custom bcrypt alphabet.
 * @function
 * @param {string} s String to decode
 * @param {number} len Maximum output length
 * @returns {!Array.<number>}
 */
 export const decodeBase64 = base64_decode;
