const fs = require('fs');
const path = require('path');

// Top 100 packages npm les plus populaires (cibles de typosquatting)
const POPULAR_PACKAGES = [
  'lodash', 'express', 'react', 'axios', 'chalk', 'commander', 'moment',
  'request', 'async', 'bluebird', 'underscore', 'uuid', 'debug', 'mkdirp',
  'glob', 'minimist', 'webpack', 'babel-core', 'typescript', 'eslint',
  'prettier', 'jest', 'mocha', 'chai', 'sinon', 'mongoose', 'sequelize',
  'mysql', 'pg', 'redis', 'mongodb', 'socket.io', 'express-session',
  'body-parser', 'cookie-parser', 'cors', 'helmet', 'morgan', 'dotenv',
  'jsonwebtoken', 'bcrypt', 'passport', 'nodemailer', 'aws-sdk', 'stripe',
  'twilio', 'firebase', 'graphql', 'apollo-server', 'next', 'nuxt',
  'gatsby', 'vue', 'angular', 'svelte', 'electron', 'puppeteer', 'cheerio',
  'sharp', 'jimp', 'canvas', 'pdf-lib', 'exceljs', 'csv-parser', 'xml2js',
  'yaml', 'ini', 'config', 'yargs', 'inquirer', 'ora', 'chalk', 'colors',
  'winston', 'bunyan', 'pino', 'log4js', 'ramda', 'rxjs', 'immutable',
  'mobx', 'redux', 'zustand', 'formik', 'yup', 'joi', 'ajv', 'validator',
  'date-fns', 'dayjs', 'luxon', 'numeral', 'accounting', 'currency.js',
  'lodash-es', 'core-js', 'regenerator-runtime', 'tslib', 'classnames',
  'prop-types', 'cross-env', 'npm', 'yarn', 'pnpm', 'node-fetch', 'got'
];

// Techniques de typosquatting connues
const TYPOSQUAT_PATTERNS = [
  { type: 'missing_char', fn: (name) => generateMissingChar(name) },
  { type: 'extra_char', fn: (name) => generateExtraChar(name) },
  { type: 'swapped_chars', fn: (name) => generateSwappedChars(name) },
  { type: 'wrong_char', fn: (name) => generateWrongChar(name) },
  { type: 'hyphen_tricks', fn: (name) => generateHyphenTricks(name) },
  { type: 'suffix_tricks', fn: (name) => generateSuffixTricks(name) }
];

async function scanTyposquatting(targetPath) {
  const threats = [];
  const packageJsonPath = path.join(targetPath, 'package.json');

  if (!fs.existsSync(packageJsonPath)) {
    return threats;
  }

  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  const dependencies = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
    ...packageJson.peerDependencies,
    ...packageJson.optionalDependencies
  };

  for (const depName of Object.keys(dependencies)) {
    const match = findTyposquatMatch(depName);
    if (match) {
      threats.push({
        type: 'typosquat_detected',
        severity: 'HIGH',
        message: `Package "${depName}" ressemble a "${match.original}" (${match.type}). Possible typosquatting.`,
        file: 'package.json',
        details: {
          suspicious: depName,
          legitimate: match.original,
          technique: match.type,
          distance: match.distance
        }
      });
    }
  }

  return threats;
}

function findTyposquatMatch(name) {
  // Ignore les packages scoped (@org/package)
  if (name.startsWith('@')) return null;

  for (const popular of POPULAR_PACKAGES) {
    // Ignore si c'est exactement le meme
    if (name === popular) continue;

    const distance = levenshteinDistance(name, popular);
    
    // Distance de 1 ou 2 = tres suspect
    if (distance === 1) {
      return {
        original: popular,
        type: detectTyposquatType(name, popular),
        distance: distance
      };
    }

    // Distance de 2 avec nom court = suspect
    if (distance === 2 && popular.length <= 6) {
      return {
        original: popular,
        type: detectTyposquatType(name, popular),
        distance: distance
      };
    }

    // Verifie les tricks de suffixe
    if (isSuffixTrick(name, popular)) {
      return {
        original: popular,
        type: 'suffix_trick',
        distance: distance
      };
    }
  }

  return null;
}

function detectTyposquatType(typo, original) {
  if (typo.length === original.length - 1) return 'missing_char';
  if (typo.length === original.length + 1) return 'extra_char';
  if (typo.length === original.length) {
    // Verifie si swap
    let diffs = 0;
    for (let i = 0; i < typo.length; i++) {
      if (typo[i] !== original[i]) diffs++;
    }
    if (diffs === 2) return 'swapped_chars';
    return 'wrong_char';
  }
  return 'unknown';
}

function isSuffixTrick(name, popular) {
  const suffixes = ['-js', '.js', '-node', '-npm', '-cli', '-api', '-lib', '-pkg', '-dev', '-pro'];
  for (const suffix of suffixes) {
    if (name === popular + suffix) return true;
    if (name === popular.replace('-', '') + suffix) return true;
  }
  // Verifie aussi les prefixes
  const prefixes = ['node-', 'npm-', 'js-', 'get-', 'the-'];
  for (const prefix of prefixes) {
    if (name === prefix + popular) return true;
  }
  return false;
}

function levenshteinDistance(a, b) {
  const matrix = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

// Generateurs pour tests (pas utilises dans le scan, mais utiles pour enrichir les IOCs)
function generateMissingChar(name) {
  const results = [];
  for (let i = 0; i < name.length; i++) {
    results.push(name.slice(0, i) + name.slice(i + 1));
  }
  return results;
}

function generateExtraChar(name) {
  const results = [];
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789-';
  for (let i = 0; i <= name.length; i++) {
    for (const char of chars) {
      results.push(name.slice(0, i) + char + name.slice(i));
    }
  }
  return results;
}

function generateSwappedChars(name) {
  const results = [];
  for (let i = 0; i < name.length - 1; i++) {
    const arr = name.split('');
    [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
    results.push(arr.join(''));
  }
  return results;
}

function generateWrongChar(name) {
  const results = [];
  const keyboard = {
    'a': 'sqwz', 'b': 'vghn', 'c': 'xdfv', 'd': 'serfcx', 'e': 'wsdfr',
    'f': 'drtgvc', 'g': 'ftyhbv', 'h': 'gyujnb', 'i': 'ujklo', 'j': 'huikmn',
    'k': 'jiolm', 'l': 'kop', 'm': 'njk', 'n': 'bhjm', 'o': 'iklp',
    'p': 'ol', 'q': 'wa', 'r': 'edft', 's': 'awedxz', 't': 'rfgy',
    'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc', 'y': 'tghu', 'z': 'asx'
  };
  for (let i = 0; i < name.length; i++) {
    const char = name[i].toLowerCase();
    if (keyboard[char]) {
      for (const replacement of keyboard[char]) {
        results.push(name.slice(0, i) + replacement + name.slice(i + 1));
      }
    }
  }
  return results;
}

function generateHyphenTricks(name) {
  const results = [];
  // Ajouter des hyphens
  for (let i = 1; i < name.length; i++) {
    results.push(name.slice(0, i) + '-' + name.slice(i));
  }
  // Retirer des hyphens
  results.push(name.replace(/-/g, ''));
  return results;
}

function generateSuffixTricks(name) {
  const suffixes = ['-js', '.js', '-node', '-npm', '-cli'];
  return suffixes.map(s => name + s);
}

module.exports = { scanTyposquatting, levenshteinDistance };