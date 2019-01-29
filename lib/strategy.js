'use strict';

const passport = require('passport-strategy');
const debug = require('debug')('passport-jd-credit');

const _ = require('lodash');
const crypto = require('crypto');
const fs = require('fs');
const rp = require('request-promise');

const url = require('url');
const util = require('util');
const utils = require('./utils');

const JSON = require('json3');
const NodeRSA = require('node-rsa');

function JDCreditStrategy(options, verify) {
  options = options || {};

  if (!verify || typeof verify !== 'function') {
    throw new TypeError('JDCreditStrategy required a verify callback');
  }

  if (!options.merchant_code) {
    throw new TypeError('JDCreditStrategy requires a merchant_code option');
  }

  if (!options.des_key) {
    throw new TypeError('JDCreditStrategy requires a des_key option');
  }

  if (!options.private_key) {
    throw new TypeError('JDCreditStrategy requires a private_key option');
  }

  if (!options.jd_credit_public_key) {
    throw new TypeError(
      'JDCreditStrategy requires a jd_credit_public_key option'
    );
  }

  passport.Strategy.call(this, options, verify);

  this.name = options.name || 'jd-credit';

  this._verify = verify;
  this._options = _.extend(
    {
      bind: 'http://opencredit.jd.com/oauth2/bind',
      unbind: 'http://opencredit.jd.com/oauth2/unbind',
      rights: 'http://opencredit.jd.com/access/rights'
    },
    options
  );
  this._callbackURL = options.callbackURL;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from 'passort.Strategy'
 */
util.inherits(JDCreditStrategy, passport.Strategy);

JDCreditStrategy.prototype.authenticate = function(req, options) {
  const self = this;

  if (!req._passport) {
    return self.error(new Error('passport.initialize() middleware not in use'));
  }

  options = options || {};

  let callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    const parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(
        utils.originalURL(req, { proxy: this._trustProxy }),
        callbackURL
      );
    }
  }

  // 获取accessToken授权成功
  if (req.query && req.query.accessToken) {
    debug('JDCredit callback -> \n %s', req.url);

    const JDCredit = _.extend(options, self._options);

    const data = JSON.stringify({
      accessToken: req.query.accessToken
    });

    let encrypted = '';
    let signed = '';

    // DES加密
    const cipher = crypto.createCipheriv('des-ecb', JDCredit.des_key, '');
    encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    encrypted =
      encrypted + ',' + new Buffer(JDCredit.des_key).toString('base64');

    // RSA加密
    encrypted = new NodeRSA(fs.readFileSync(JDCredit.jd_credit_public_key), {
      encryptionScheme: 'pkcs1'
    }).encrypt(encrypted, 'base64');

    // RSA签名
    signed = crypto
      .createSign('RSA-MD5')
      .update(new Buffer(encrypted, 'utf8'))
      .sign(fs.readFileSync(JDCredit.private_key), 'base64');

    const form = {
      merchantCode: JDCredit.merchant_code,
      data: encodeURIComponent(encrypted + ',' + signed)
    };
    debug('JDCredit access rights params -> \n %s', JSON.stringify(form));

    rp({
      url: JDCredit.rights,
      method: 'POST',
      form: form,
      json: true
    })
      .then(function(response) {
        debug('JDCredit rights return -> \n %s', JSON.stringify(response));

        // 校验完成信息
        function verified(err, user, info) {
          if (err) {
            return self.error(err);
          }
          if (!user) {
            return self.fail(info);
          }
          self.success(user, info);
        }

        if (
          response &&
          response.isSuccess &&
          response.responseCode === '0000'
        ) {
          const data = decodeURIComponent(response.data);

          const encrypted = data.split(',')[0];
          const signed = data.split(',')[1];

          if (
            crypto
              .createVerify('RSA-MD5')
              .update(new Buffer(encrypted, 'utf8'))
              .verify(
                fs.readFileSync(JDCredit.jd_credit_public_key),
                signed,
                'base64'
              )
          ) {
            const decrypted = new NodeRSA(
              fs.readFileSync(JDCredit.private_key),
              {
                encryptionScheme: 'pkcs1'
              }
            ).decrypt(encrypted, 'utf8');

            const strs = decrypted.split(',');

            const decipher = crypto.createDecipheriv(
              'des-ecb',
              new Buffer(strs[1], 'base64'),
              ''
            );
            let json = decipher.update(strs[0], 'base64', 'utf8');
            json += decipher.final('utf8');

            const result = JSON.parse(json);
            debug('fetch user info -> \n %s', json);

            const profile = {
              id: result.openId,
              open_id: result.openId,
              username: result['205'],
              name: result['204'],
              score: result['101'],
              grade: result['102']
            };

            try {
              if (self._passReqToCallback) {
                self._verify(
                  req,
                  req.query.accessToken,
                  req.query.accessToken,
                  profile,
                  verified
                );
              } else {
                self._verify(
                  req.query.accessToken,
                  req.query.accessToken,
                  profile,
                  verified
                );
              }
            } catch (ex) {
              return self.error(ex);
            }
          } else {
            self.error(new Error());
          }
        } else {
          self.error(new Error(response.responseMessage));
        }
      })
      .catch(function(err) {
        self.error(err);
      });
  } else {
    const merchant_code = options.merchant_code || self._options.merchant_code;

    const authorizeURL =
      (options.bind || self._options.bind) +
      '?merchantCode=' +
      merchant_code +
      '&callBack=' +
      encodeURIComponent(callbackURL);
    debug('redirect -> \n%s', url);

    self.redirect(authorizeURL, 302);
  }
};

module.exports = JDCreditStrategy;
