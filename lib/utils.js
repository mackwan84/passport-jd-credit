'use strict';

exports.merge = require('utils-merge');

exports.originalURL = function(req, options) {
  options = options || {};
  const app = req.app;
  if (app && app.get && app.get('trust proxy')) {
    options.proxy = true;
  }
  const trustProxy = options.proxy;

  const proto = (req.headers['x-forwarded-proto'] || '').toLowerCase(),
    tls =
      req.connection.encrypted ||
      (trustProxy && proto.split(/\s*,\s*/)[0] === 'https'),
    host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host,
    protocol = tls ? 'https' : 'http',
    path = req.url || '';
  return protocol + '://' + host + path;
};
