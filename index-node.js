import { webcrypto } from 'node:crypto';
import { setCrypto } from './src/bcrypt.js';
export * from './src/bcrypt.js';

setCrypto(webcrypto);
