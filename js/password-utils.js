/**
 * PasswordUtils v1.1
 * Cryptographically secure password generator with URL hash API support
 * UMD module: works with AMD, CommonJS, or as global variable
 */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PasswordUtils = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ============================================================================
  // CONFIGURATION
  // ============================================================================
  const CONFIG = {
    MIN_LENGTH: 4,
    MAX_LENGTH: 4096,           // Increased for extreme use cases
    DEFAULT_LENGTH: 16,
    WARN_LENGTH: 2048,          // Show console warning above this
    CHARSET_NAMES: {
      lower: 'lowercase',
      upper: 'uppercase',
      digits: 'digits',
      symbols: 'symbols'
    }
  };

  // Standard character sets
  const CHAR_SETS = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.<>/?'
  };

  // Safe sets: exclude visually ambiguous characters (i/l/1/O/0)
  const SAFE_SETS = {
    lower: 'abcdefghjkmnpqrstuvwxyz',   // removed i, l, o
    upper: 'ABCDEFGHJKMNPQRSTUVWXYZ',   // removed I, L, O
    digits: '23456789',                 // removed 0, 1
    symbols: '!@#$%^&*()-_=+[]{};:,.<>/?'
  };

  // Extended symbols set (optional, for high-entropy needs)
  const EXTENDED_SYMBOLS = CHAR_SETS.symbols + '`~\\|\'"';

  // ============================================================================
  // CRYPTO-SECURE RANDOM NUMBER GENERATOR (no modulo bias)
  // ============================================================================
  function secureRandomInt(max) {
    if (!window.crypto || !window.crypto.getRandomValues) {
      throw new Error('Cryptographically secure random generation is not supported in this environment');
    }
    if (max <= 0 || !Number.isInteger(max)) {
      throw new Error('secureRandomInt: max must be a positive integer');
    }

    const MAX_UINT32 = 0xFFFFFFFF;
    const limit = MAX_UINT32 - (MAX_UINT32 % max);

    let rand;
    do {
      rand = window.crypto.getRandomValues(new Uint32Array(1))[0];
    } while (rand >= limit);

    return rand % max;
  }

  // ============================================================================
  // PASSWORD GENERATION
  // ============================================================================
  function generatePassword(length, options = {}) {
    // Validate length
    if (!Number.isInteger(length)) {
      throw new TypeError('Length must be an integer');
    }
    if (length < CONFIG.MIN_LENGTH || length > CONFIG.MAX_LENGTH) {
      throw new RangeError(`Length must be between ${CONFIG.MIN_LENGTH} and ${CONFIG.MAX_LENGTH}`);
    }
    if (length > CONFIG.WARN_LENGTH) {
      console.warn(`Generating ${length}-char password may impact performance`);
    }

    // Normalize options
    const opts = {
      lower: !!options.lower,
      upper: !!options.upper,
      digits: !!options.digits,
      symbols: !!options.symbols,
      safe: !!options.safe,
      extendedSymbols: !!options.extendedSymbols
    };

    // At least one charset must be enabled
    if (!opts.lower && !opts.upper && !opts.digits && !opts.symbols) {
      throw new Error('At least one character set must be enabled (lower/upper/digits/symbols)');
    }

    // Select character sets
    const baseSets = opts.safe ? SAFE_SETS : CHAR_SETS;
    const symbolsSet = opts.extendedSymbols ? EXTENDED_SYMBOLS : baseSets.symbols;

    const pool = [];
    const required = [];

    if (opts.lower) {
      const set = baseSets.lower;
      pool.push(...set);
      required.push(set[secureRandomInt(set.length)]);
    }
    if (opts.upper) {
      const set = baseSets.upper;
      pool.push(...set);
      required.push(set[secureRandomInt(set.length)]);
    }
    if (opts.digits) {
      const set = baseSets.digits;
      pool.push(...set);
      required.push(set[secureRandomInt(set.length)]);
    }
    if (opts.symbols) {
      const set = symbolsSet;
      pool.push(...set);
      required.push(set[secureRandomInt(set.length)]);
    }

    if (pool.length === 0) {
      throw new Error('Character pool is empty — check your options');
    }

    // Build password: start with required chars, fill the rest randomly
    const result = [...required];
    while (result.length < length) {
      result.push(pool[secureRandomInt(pool.length)]);
    }

    // Fisher-Yates shuffle with crypto-random indices
    for (let i = result.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [result[i], result[j]] = [result[j], result[i]];
    }

    return result.join('');
  }

  // ============================================================================
  // URL HASH PARSER
  // Format: #length-sets,mode
  // Sets: az, AZ, 09, sym, safe, extended
  // Modes: json, plain
  // Example: #32-az,AZ,09,sym,json
  // ============================================================================
  function parseHash(hash) {
    if (!hash || typeof hash !== 'string' || !hash.startsWith('#')) {
      return null;
    }

    const clean = hash.slice(1).trim();
    if (!clean) return null;

    const parts = clean.split('-');
    if (parts.length < 2) return null;

    const length = parseInt(parts[0], 10);
    if (isNaN(length)) return null;

    const tokens = parts[1].split(',').map(t => t.trim().toLowerCase()).filter(Boolean);

    // Build config with smart defaults
    const config = {
      length: clamp(length, CONFIG.MIN_LENGTH, CONFIG.MAX_LENGTH),
      lower: tokens.includes('az') || tokens.includes('lower'),
      upper: tokens.includes('AZ') || tokens.includes('upper'),
      digits: tokens.includes('09') || tokens.includes('digits'),
      symbols: tokens.includes('sym') || tokens.includes('symbols'),
      safe: tokens.includes('safe'),
      extendedSymbols: tokens.includes('extended') || tokens.includes('ext'),
      json: tokens.includes('json'),
      plain: tokens.includes('plain')
    };

    // If no charset specified, enable all by default (except extended)
    if (!config.lower && !config.upper && !config.digits && !config.symbols) {
      config.lower = true;
      config.upper = true;
      config.digits = true;
      config.symbols = true;
    }

    return config;
  }

  // ============================================================================
  // ENTROPY & STRENGTH UTILITIES
  // ============================================================================
  function calculateEntropy(length, options = {}) {
    let poolSize = 0;
    const sets = options.safe ? SAFE_SETS : CHAR_SETS;
    const symbolsSet = options.extendedSymbols ? EXTENDED_SYMBOLS : sets.symbols;

    if (options.lower) poolSize += sets.lower.length;
    if (options.upper) poolSize += sets.upper.length;
    if (options.digits) poolSize += sets.digits.length;
    if (options.symbols) poolSize += symbolsSet.length;

    if (poolSize === 0) return 0;
    return length * Math.log2(poolSize);
  }

  function estimateStrength(entropy) {
    if (entropy < 28) return { level: 'weak', label: 'Weak', color: '#ef4444' };
    if (entropy < 36) return { level: 'fair', label: 'Fair', color: '#f59e0b' };
    if (entropy < 60) return { level: 'good', label: 'Good', color: '#22c55e' };
    if (entropy < 128) return { level: 'strong', label: 'Strong', color: '#10b981' };
    return { level: 'excellent', label: 'Excellent', color: '#059669' };
  }

  function getPasswordMetrics(password, options = {}) {
    const entropy = calculateEntropy(password.length, options);
    const strength = estimateStrength(entropy);
    return {
      length: password.length,
      entropy: Math.round(entropy * 100) / 100,
      strength: strength.level,
      strengthLabel: strength.label,
      strengthColor: strength.color,
      estimatedCrackTime: estimateCrackTime(entropy)
    };
  }

  function estimateCrackTime(entropy) {
    // Assumptions: 10 billion guesses/sec (GPU cluster), online attack slower
    const guessesPerSec = 1e10;
    const seconds = Math.pow(2, entropy) / guessesPerSec / 2; // average case

    if (seconds < 1) return 'instantly';
    if (seconds < 60) return 'seconds';
    if (seconds < 3600) return 'minutes';
    if (seconds < 86400) return 'hours';
    if (seconds < 31536000) return 'days';
    if (seconds < 31536000 * 100) return 'years';
    if (seconds < 31536000 * 1000000) return 'centuries';
    return 'forever';
  }

  // ============================================================================
  // HELPERS
  // ============================================================================
  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  function getCharSetInfo(options = {}) {
    const sets = options.safe ? SAFE_SETS : CHAR_SETS;
    const symbolsSet = options.extendedSymbols ? EXTENDED_SYMBOLS : sets.symbols;
    const result = {};

    if (options.lower) result.lowercase = sets.lower.length;
    if (options.upper) result.uppercase = sets.upper.length;
    if (options.digits) result.digits = sets.digits.length;
    if (options.symbols) result.symbols = symbolsSet.length;

    return result;
  }

  // ============================================================================
  // PUBLIC API
  // ============================================================================
  return {
    // Core
    generatePassword,
    parseHash,

    // Metrics
    calculateEntropy,
    estimateStrength,
    getPasswordMetrics,
    estimateCrackTime,

    // Info
    getCharSetInfo,
    getCharSets: () => ({ ...CHAR_SETS }),
    getSafeSets: () => ({ ...SAFE_SETS }),
    getExtendedSymbols: () => EXTENDED_SYMBOLS,

    // Config
    CONFIG: { ...CONFIG },

    // Utils
    secureRandomInt,
    clamp
  };
}));
