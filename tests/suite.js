import * as assert from 'node:assert/strict'
import * as path from "path"
import * as fs from "fs"
import * as binding from "bcrypt"
import * as bcrypt from '../index-node.js'
    
const suite = {

    "encodeBase64": function(test) {
        var str = bcrypt.encodeBase64([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10], 16);
        test.strictEqual(str, "..CA.uOD/eaGAOmJB.yMBu");
        test.done();
    },

    "decodeBase64": function(test) {
        var bytes = bcrypt.decodeBase64("..CA.uOD/eaGAOmJB.yMBv.", 16);
        test.deepEqual(bytes, [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
        test.done();
    },
    
    "genSaltSync": function(test) {
        var salt = bcrypt.genSaltSync(10);
        test.ok(salt);
        test.ok(typeof salt == 'string');
        test.ok(salt.length > 0);
        test.done();
    },
    
    "genSalt": async function(test) {
        const salt = await bcrypt.genSalt(10)
        test.ok(salt);
        test.ok(typeof salt == 'string');
        test.ok(salt.length > 0);
        test.done();
    },
    
    "hashSync": function(test) {
        test.doesNotThrow(function() {
            bcrypt.hashSync("hello", 10);
        });
        test.notEqual(bcrypt.hashSync("hello", 10), bcrypt.hashSync("hello", 10));
        test.done();
    },
    
    "hash": function(test) {
        bcrypt.hash("hello", 10, function(err, hash) {
            test.notOk(err);
            test.ok(hash);
            test.done();
        });
    },
    
    "compareSync": function(test) {
        var salt1 = bcrypt.genSaltSync(),
            hash1 = bcrypt.hashSync("hello", salt1); // $2a$
        var salt2 = bcrypt.genSaltSync().replace(/\$2a\$/, "$2y$"),
            hash2 = bcrypt.hashSync("world", salt2);
        var salt3 = bcrypt.genSaltSync().replace(/\$2a\$/, "$2b$"),
            hash3 = bcrypt.hashSync("hello world", salt3);

        test.strictEqual(hash1.substring(0,4), "$2a$");
        test.ok(bcrypt.compareSync("hello", hash1));
        test.notOk(bcrypt.compareSync("hello", hash2));
        test.notOk(bcrypt.compareSync("hello", hash3));

        test.strictEqual(hash2.substring(0,4), "$2y$");
        test.ok(bcrypt.compareSync("world", hash2));
        test.notOk(bcrypt.compareSync("world", hash1));
        test.notOk(bcrypt.compareSync("world", hash3));

        test.strictEqual(hash3.substring(0,4), "$2b$");
        test.ok(bcrypt.compareSync("hello world", hash3));
        test.notOk(bcrypt.compareSync("hello world", hash1));
        test.notOk(bcrypt.compareSync("hello world", hash2));

        test.done();
    },
    
    "compare": function(test) {
        var salt1 = bcrypt.genSaltSync(),
            hash1 = bcrypt.hashSync("hello", salt1); // $2a$
        var salt2 = bcrypt.genSaltSync();
        salt2 = salt2.substring(0,2)+'y'+salt2.substring(3); // $2y$
        var hash2 = bcrypt.hashSync("world", salt2);
        bcrypt.compare("hello", hash1, function(err, same) {
            test.notOk(err);
            test.ok(same);
            bcrypt.compare("hello", hash2, function(err, same) {
                test.notOk(err);
                test.notOk(same);
                bcrypt.compare("world", hash2, function(err, same) {
                    test.notOk(err);
                    test.ok(same);
                    bcrypt.compare("world", hash1, function(err, same) {
                        test.notOk(err);
                        test.notOk(same);
                        test.done();
                    });
                });
            });
        });
    },
    
    "getSalt": function(test) {
        var hash1 = bcrypt.hashSync("hello", bcrypt.genSaltSync());
        var salt = bcrypt.getSalt(hash1);
        var hash2 = bcrypt.hashSync("hello", salt);
        test.equal(hash1, hash2);
        test.done();
    },
    
    "getRounds": function(test) {
        var hash1 = bcrypt.hashSync("hello", bcrypt.genSaltSync());
        test.equal(bcrypt.getRounds(hash1), 10);
        test.done();
    },
   
    "progress": function(test) {
        bcrypt.genSalt(12, function(err, salt) {
            test.ok(!err);
            var progress = [];
            bcrypt.hash("hello world", salt, function(err, hash) {
                test.ok(!err);
                test.ok(typeof hash === 'string');
                test.ok(progress.length >= 2);
                test.strictEqual(progress[0], 0);
                test.strictEqual(progress[progress.length-1], 1);
                test.done();
            }, function(n) {
                progress.push(n);
            });
        });
    },

    "promise": function(test) {
        bcrypt.genSalt(10)
        .then(function(salt) {
            bcrypt.hash("hello", salt)
            .then(function(hash) {
                test.ok(hash);
                bcrypt.compare("hello", hash)
                .then(function(result) {
                    test.ok(result);
                    bcrypt.genSalt(/* no args */)
                    .then(function(salt) {
                        test.ok(salt);
                        test.done();
                    }, function(err) {
                        test.fail(err, null, "promise rejected");
                    });
                }, function(err) {
                    test.fail(err, null, "promise rejected");
                });
            }, function(err) {
                test.fail(err, null, 'promise rejected');
            });
        }, function(err) {
            test.fail(err, null, "promise rejected");
        });
    },

    "compat:quickbrown": function(test) {
        var pass = fs.readFileSync(new URL("quickbrown.txt", import.meta.url), 'utf-8');
        var salt = bcrypt.genSaltSync();
        var expected = binding.hashSync(pass, salt);
        var actual = bcrypt.hashSync(pass, salt);
        assert.equal(actual, expected);
        test.done();
    },

    "compat:roundsOOB": function(test) {
        var salt1 = bcrypt.genSaltSync(0), // $10$ like not set
            salt2 = bindingConvert(binding.genSaltSync(0));
        test.strictEqual(salt1.substring(0, 7), "$2a$10$");
        test.strictEqual(salt2.substring(0, 7), "$2a$10$");

        salt1 = bcrypt.genSaltSync(3); // $04$ is lower cap
        salt2 = bcrypt.genSaltSync(3);
        test.strictEqual(salt1.substring(0, 7), "$2a$04$");
        test.strictEqual(salt2.substring(0, 7), "$2a$04$");

        salt1 = bcrypt.genSaltSync(32); // $31$ is upper cap
        salt2 = bcrypt.genSaltSync(32);
        test.strictEqual(salt1.substring(0, 7), "$2a$31$");
        test.strictEqual(salt2.substring(0, 7), "$2a$31$");

        test.done();
    },
};

// TODO: implement the $2b$ hash version
function bindingConvert(v) {
    if (v.startsWith("$2b$")) return v.replace("$2b", "$2a")
    throw new Error('Expected $2b$ hash')
}

for (const [testName, testCase] of Object.entries(suite)) {
    console.log('Running '+ testName+'...')
    try {
        await new Promise((resolve, reject) => {
            const test = {
                ...assert,
                done() { resolve() },
                fail(err) { reject(err) },
                notOk(v) { assert.ok(!v) },
            }
            Promise.resolve().then(() => testCase(test)).then(resolve, reject)
        })
        console.log('    ok')
    } catch(e) {
        console.error(e)
        process.exit(1)
    }
}
