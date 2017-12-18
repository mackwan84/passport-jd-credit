'use strict';

var util = require('util');
var passport = require('passport-strategy');
var debug = require('debug')('passport-jd-credit');

var _ = require('lodash');
var crypto = require('crypto');
var fs = require('fs');
var path = require('path');
var rp = require('request-promise');
var url = require('url');

var JSON = require('json3');
var Promise = require('bluebird');
var NodeRSA = require('node-rsa');

function JDCreditStrategy(options, verify) {
    options = options || {};

    if (!verify) {
        throw new TypeError('JDCreditStrategy required a verify callback');
    }

    if (typeof verify !== 'function') {
        throw new TypeError('_verify must be function');
    }

    if (!options.app_id) {
        throw new TypeError('JDCreditStrategy requires a app_id option');
    }

    passport.Strategy.call(this, options, verify);

    this.name = options.name || 'JDCredit';

    this._verify = verify;
    this._options = _.extend(options, {
        bind: 'http://opencredit.jd.com/oauth2/bind',
        unbind: 'http://opencredit.jd.com/oauth2/unbind',
        rights: 'http://opencredit.jd.com/access/rights'
    });
    this._callbackURL = options.callbackURL;
    this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from 'passort.Strategy'
 */
util.inherits(JDCreditStrategy, passport.Strategy);

JDCreditStrategy.prototype.authenticate = function(req, options) {
    var self = this;

    if (!req._passport) {
        return self.error(new Error('passport.initialize() middleware not in use'));
    }

    options = options || {};

    // 获取accessToken授权成功
    if (req.query && req.query.accessToken) {
        debug('JDCredit callback -> \n %s', req.url);

        var JDCredit = _.extend(options, self._options);

        var data = JSON.stringify({
            accessToken: req.query.accessToken
        });

        var encrypted = '';
        var signed = '';

        // DES加密
        var cipher = crypto.createCipheriv('des-ecb', JDCredit.des_key, '');
        encrypted = cipher.update(data, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        encrypted = encrypted + ',' + new Buffer(JDCredit.des_key).toString('base64');

        // RSA加密
        encrypted = new NodeRSA(fs.readFileSync(JDCredit.jd_credit_public_key), {
            encryptionScheme: 'pkcs1'
        }).encrypt(encrypted, 'base64');

        // RSA签名
        signed = crypto.createSign('RSA-MD5').update(new Buffer(encrypted, 'utf8')).sign(fs.readFileSync(JDCredit.private_key), 'base64');

        var form = {
            merchantCode: JDCredit.merchantCode,
            data: encodeURIComponent(encrypted + ',' + signed)
        };

        rp({
            url: JDCredit.rights,
            method: 'POST',
            form: form,
            json: true
        }).then(function(response) {
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

            if (response && response.isSuccess && response.responseCode === '0000') {
                var data = decodeURIComponent(response.data);

                var encrypted = data.split(',')[0];
                var signed = data.split(',')[1];

                if (crypto.createVerify('RSA-MD5').update(new Buffer(encrypted, 'utf8')).verify(fs.readFileSync(JDCredit.jd_credit_public_key), signed, 'base64')) {
                    var decrypted = new NodeRSA(fs.readFileSync(JDCredit.private_key), {
                        encryptionScheme: 'pkcs1'
                    }).decrypt(encrypted, 'utf8');

                    var strs = decrypted.split(',');

                    var decipher = crypto.createDecipheriv('des-ecb', new Buffer(strs[1], 'base64'), '');
                    var json = decipher.update(strs[0], 'base64', 'utf8');
                    json += decipher.final('utf8');

                    var result = JSON.parse(json);
                    debug('fetch user info -> \n %s', json);

                    var profile = {
                        id: profile.openId,
                        user_id: profile.openId,
                        username: profile['205'],
                        score: profile['101'],
                        grade: profile['102']
                    };

                    try {
                        if (self._passReqToCallback) {
                            self._verify(req, req.query.accessToken, req.query.accessToken, profile, verified);
                        } else {
                            self._verify(req.query.accessToken, req.query.accessToken, profile, verified);
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
        }).catch(function(err) {
            self.error(err);
        });
    } else {
        var merchant_code = options.merchant_code || self._options.merchant_code;
        var callbackURL = options.callbackURL || self._callbackURL;

        var url = (options.bind || self._options.bind) + '?merchantCode=' + merchant_code + '&callBack=' + encodeURIComponent(callbackURL);
        debug('redirect -> \n%s', url);

        self.redirect(url, 302);
    }
};

module.exports = JDCreditStrategy;