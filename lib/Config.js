"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = exports.Config = void 0;

var _cache = _interopRequireDefault(require("./cache"));

var _SchemaCache = _interopRequireDefault(require("./Controllers/SchemaCache"));

var _DatabaseController = _interopRequireDefault(require("./Controllers/DatabaseController"));

var _net = _interopRequireDefault(require("net"));

var _Definitions = require("./Options/Definitions");

var _lodash = require("lodash");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// A Config object provides information about how a specific app is
// configured.
// mount is the URL for the root of the API; includes http, domain, etc.
function removeTrailingSlash(str) {
  if (!str) {
    return str;
  }

  if (str.endsWith('/')) {
    str = str.substr(0, str.length - 1);
  }

  return str;
}

class Config {
  static get(applicationId, mount) {
    const cacheInfo = _cache.default.get(applicationId);

    if (!cacheInfo) {
      return;
    }

    const config = new Config();
    config.applicationId = applicationId;
    Object.keys(cacheInfo).forEach(key => {
      if (key == 'databaseController') {
        const schemaCache = new _SchemaCache.default(cacheInfo.cacheController, cacheInfo.schemaCacheTTL, cacheInfo.enableSingleSchemaCache);
        config.database = new _DatabaseController.default(cacheInfo.databaseController.adapter, schemaCache);
      } else {
        config[key] = cacheInfo[key];
      }
    });
    config.mount = removeTrailingSlash(mount);
    config.generateSessionExpiresAt = config.generateSessionExpiresAt.bind(config);
    config.generateEmailVerifyTokenExpiresAt = config.generateEmailVerifyTokenExpiresAt.bind(config);
    return config;
  }

  static put(serverConfiguration) {
    Config.validate(serverConfiguration);

    _cache.default.put(serverConfiguration.appId, serverConfiguration);

    Config.setupPasswordValidator(serverConfiguration.passwordPolicy);
    return serverConfiguration;
  }

  static validate({
    verifyUserEmails,
    userController,
    appName,
    publicServerURL,
    revokeSessionOnPasswordReset,
    expireInactiveSessions,
    sessionLength,
    maxLimit,
    emailVerifyTokenValidityDuration,
    accountLockout,
    passwordPolicy,
    masterKeyIps,
    masterKey,
    readOnlyMasterKey,
    allowHeaders,
    idempotencyOptions,
    emailVerifyTokenReuseIfValid,
    fileUpload
  }) {
    if (masterKey === readOnlyMasterKey) {
      throw new Error('masterKey and readOnlyMasterKey should be different');
    }

    const emailAdapter = userController.adapter;

    if (verifyUserEmails) {
      this.validateEmailConfiguration({
        emailAdapter,
        appName,
        publicServerURL,
        emailVerifyTokenValidityDuration,
        emailVerifyTokenReuseIfValid
      });
    }

    this.validateAccountLockoutPolicy(accountLockout);
    this.validatePasswordPolicy(passwordPolicy);
    this.validateFileUploadOptions(fileUpload);

    if (typeof revokeSessionOnPasswordReset !== 'boolean') {
      throw 'revokeSessionOnPasswordReset must be a boolean value';
    }

    if (publicServerURL) {
      if (!publicServerURL.startsWith('http://') && !publicServerURL.startsWith('https://')) {
        throw 'publicServerURL should be a valid HTTPS URL starting with https://';
      }
    }

    this.validateSessionConfiguration(sessionLength, expireInactiveSessions);
    this.validateMasterKeyIps(masterKeyIps);
    this.validateMaxLimit(maxLimit);
    this.validateAllowHeaders(allowHeaders);
    this.validateIdempotencyOptions(idempotencyOptions);
  }

  static validateIdempotencyOptions(idempotencyOptions) {
    if (!idempotencyOptions) {
      return;
    }

    if (idempotencyOptions.ttl === undefined) {
      idempotencyOptions.ttl = _Definitions.IdempotencyOptions.ttl.default;
    } else if (!isNaN(idempotencyOptions.ttl) && idempotencyOptions.ttl <= 0) {
      throw 'idempotency TTL value must be greater than 0 seconds';
    } else if (isNaN(idempotencyOptions.ttl)) {
      throw 'idempotency TTL value must be a number';
    }

    if (!idempotencyOptions.paths) {
      idempotencyOptions.paths = _Definitions.IdempotencyOptions.paths.default;
    } else if (!(idempotencyOptions.paths instanceof Array)) {
      throw 'idempotency paths must be of an array of strings';
    }
  }

  static validateAccountLockoutPolicy(accountLockout) {
    if (accountLockout) {
      if (typeof accountLockout.duration !== 'number' || accountLockout.duration <= 0 || accountLockout.duration > 99999) {
        throw 'Account lockout duration should be greater than 0 and less than 100000';
      }

      if (!Number.isInteger(accountLockout.threshold) || accountLockout.threshold < 1 || accountLockout.threshold > 999) {
        throw 'Account lockout threshold should be an integer greater than 0 and less than 1000';
      }

      if (accountLockout.unlockOnPasswordReset === undefined) {
        accountLockout.unlockOnPasswordReset = _Definitions.AccountLockoutOptions.unlockOnPasswordReset.default;
      } else if (!(0, _lodash.isBoolean)(accountLockout.unlockOnPasswordReset)) {
        throw 'Parse Server option accountLockout.unlockOnPasswordReset must be a boolean.';
      }
    }
  }

  static validatePasswordPolicy(passwordPolicy) {
    if (passwordPolicy) {
      if (passwordPolicy.maxPasswordAge !== undefined && (typeof passwordPolicy.maxPasswordAge !== 'number' || passwordPolicy.maxPasswordAge < 0)) {
        throw 'passwordPolicy.maxPasswordAge must be a positive number';
      }

      if (passwordPolicy.resetTokenValidityDuration !== undefined && (typeof passwordPolicy.resetTokenValidityDuration !== 'number' || passwordPolicy.resetTokenValidityDuration <= 0)) {
        throw 'passwordPolicy.resetTokenValidityDuration must be a positive number';
      }

      if (passwordPolicy.validatorPattern) {
        if (typeof passwordPolicy.validatorPattern === 'string') {
          passwordPolicy.validatorPattern = new RegExp(passwordPolicy.validatorPattern);
        } else if (!(passwordPolicy.validatorPattern instanceof RegExp)) {
          throw 'passwordPolicy.validatorPattern must be a regex string or RegExp object.';
        }
      }

      if (passwordPolicy.validatorCallback && typeof passwordPolicy.validatorCallback !== 'function') {
        throw 'passwordPolicy.validatorCallback must be a function.';
      }

      if (passwordPolicy.doNotAllowUsername && typeof passwordPolicy.doNotAllowUsername !== 'boolean') {
        throw 'passwordPolicy.doNotAllowUsername must be a boolean value.';
      }

      if (passwordPolicy.maxPasswordHistory && (!Number.isInteger(passwordPolicy.maxPasswordHistory) || passwordPolicy.maxPasswordHistory <= 0 || passwordPolicy.maxPasswordHistory > 20)) {
        throw 'passwordPolicy.maxPasswordHistory must be an integer ranging 0 - 20';
      }

      if (passwordPolicy.resetTokenReuseIfValid && typeof passwordPolicy.resetTokenReuseIfValid !== 'boolean') {
        throw 'resetTokenReuseIfValid must be a boolean value';
      }

      if (passwordPolicy.resetTokenReuseIfValid && !passwordPolicy.resetTokenValidityDuration) {
        throw 'You cannot use resetTokenReuseIfValid without resetTokenValidityDuration';
      }
    }
  } // if the passwordPolicy.validatorPattern is configured then setup a callback to process the pattern


  static setupPasswordValidator(passwordPolicy) {
    if (passwordPolicy && passwordPolicy.validatorPattern) {
      passwordPolicy.patternValidator = value => {
        return passwordPolicy.validatorPattern.test(value);
      };
    }
  }

  static validateEmailConfiguration({
    emailAdapter,
    appName,
    publicServerURL,
    emailVerifyTokenValidityDuration,
    emailVerifyTokenReuseIfValid
  }) {
    if (!emailAdapter) {
      throw 'An emailAdapter is required for e-mail verification and password resets.';
    }

    if (typeof appName !== 'string') {
      throw 'An app name is required for e-mail verification and password resets.';
    }

    if (typeof publicServerURL !== 'string') {
      throw 'A public server url is required for e-mail verification and password resets.';
    }

    if (emailVerifyTokenValidityDuration) {
      if (isNaN(emailVerifyTokenValidityDuration)) {
        throw 'Email verify token validity duration must be a valid number.';
      } else if (emailVerifyTokenValidityDuration <= 0) {
        throw 'Email verify token validity duration must be a value greater than 0.';
      }
    }

    if (emailVerifyTokenReuseIfValid && typeof emailVerifyTokenReuseIfValid !== 'boolean') {
      throw 'emailVerifyTokenReuseIfValid must be a boolean value';
    }

    if (emailVerifyTokenReuseIfValid && !emailVerifyTokenValidityDuration) {
      throw 'You cannot use emailVerifyTokenReuseIfValid without emailVerifyTokenValidityDuration';
    }
  }

  static validateFileUploadOptions(fileUpload) {
    try {
      if (fileUpload == null || typeof fileUpload !== 'object' || fileUpload instanceof Array) {
        throw 'fileUpload must be an object value.';
      }
    } catch (e) {
      if (e instanceof ReferenceError) {
        return;
      }

      throw e;
    }

    if (fileUpload.enableForAnonymousUser === undefined) {
      fileUpload.enableForAnonymousUser = _Definitions.FileUploadOptions.enableForAnonymousUser.default;
    } else if (typeof fileUpload.enableForAnonymousUser !== 'boolean') {
      throw 'fileUpload.enableForAnonymousUser must be a boolean value.';
    }

    if (fileUpload.enableForPublic === undefined) {
      fileUpload.enableForPublic = _Definitions.FileUploadOptions.enableForPublic.default;
    } else if (typeof fileUpload.enableForPublic !== 'boolean') {
      throw 'fileUpload.enableForPublic must be a boolean value.';
    }

    if (fileUpload.enableForAuthenticatedUser === undefined) {
      fileUpload.enableForAuthenticatedUser = _Definitions.FileUploadOptions.enableForAuthenticatedUser.default;
    } else if (typeof fileUpload.enableForAuthenticatedUser !== 'boolean') {
      throw 'fileUpload.enableForAuthenticatedUser must be a boolean value.';
    }
  }

  static validateMasterKeyIps(masterKeyIps) {
    for (const ip of masterKeyIps) {
      if (!_net.default.isIP(ip)) {
        throw `Invalid ip in masterKeyIps: ${ip}`;
      }
    }
  }

  get mount() {
    var mount = this._mount;

    if (this.publicServerURL) {
      mount = this.publicServerURL;
    }

    return mount;
  }

  set mount(newValue) {
    this._mount = newValue;
  }

  static validateSessionConfiguration(sessionLength, expireInactiveSessions) {
    if (expireInactiveSessions) {
      if (isNaN(sessionLength)) {
        throw 'Session length must be a valid number.';
      } else if (sessionLength <= 0) {
        throw 'Session length must be a value greater than 0.';
      }
    }
  }

  static validateMaxLimit(maxLimit) {
    if (maxLimit <= 0) {
      throw 'Max limit must be a value greater than 0.';
    }
  }

  static validateAllowHeaders(allowHeaders) {
    if (![null, undefined].includes(allowHeaders)) {
      if (Array.isArray(allowHeaders)) {
        allowHeaders.forEach(header => {
          if (typeof header !== 'string') {
            throw 'Allow headers must only contain strings';
          } else if (!header.trim().length) {
            throw 'Allow headers must not contain empty strings';
          }
        });
      } else {
        throw 'Allow headers must be an array';
      }
    }
  }

  generateEmailVerifyTokenExpiresAt() {
    if (!this.verifyUserEmails || !this.emailVerifyTokenValidityDuration) {
      return undefined;
    }

    var now = new Date();
    return new Date(now.getTime() + this.emailVerifyTokenValidityDuration * 1000);
  }

  generatePasswordResetTokenExpiresAt() {
    if (!this.passwordPolicy || !this.passwordPolicy.resetTokenValidityDuration) {
      return undefined;
    }

    const now = new Date();
    return new Date(now.getTime() + this.passwordPolicy.resetTokenValidityDuration * 1000);
  }

  generateSessionExpiresAt() {
    if (!this.expireInactiveSessions) {
      return undefined;
    }

    var now = new Date();
    return new Date(now.getTime() + this.sessionLength * 1000);
  }

  get invalidLinkURL() {
    return this.customPages.invalidLink || `${this.publicServerURL}/apps/invalid_link.html`;
  }

  get invalidVerificationLinkURL() {
    return this.customPages.invalidVerificationLink || `${this.publicServerURL}/apps/invalid_verification_link.html`;
  }

  get linkSendSuccessURL() {
    return this.customPages.linkSendSuccess || `${this.publicServerURL}/apps/link_send_success.html`;
  }

  get linkSendFailURL() {
    return this.customPages.linkSendFail || `${this.publicServerURL}/apps/link_send_fail.html`;
  }

  get verifyEmailSuccessURL() {
    return this.customPages.verifyEmailSuccess || `${this.publicServerURL}/apps/verify_email_success.html`;
  }

  get choosePasswordURL() {
    return this.customPages.choosePassword || `${this.publicServerURL}/apps/choose_password`;
  }

  get requestResetPasswordURL() {
    return `${this.publicServerURL}/apps/${this.applicationId}/request_password_reset`;
  }

  get passwordResetSuccessURL() {
    return this.customPages.passwordResetSuccess || `${this.publicServerURL}/apps/password_reset_success.html`;
  }

  get parseFrameURL() {
    return this.customPages.parseFrameURL;
  }

  get verifyEmailURL() {
    return `${this.publicServerURL}/apps/${this.applicationId}/verify_email`;
  }

}

exports.Config = Config;
var _default = Config;
exports.default = _default;
module.exports = Config;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9Db25maWcuanMiXSwibmFtZXMiOlsicmVtb3ZlVHJhaWxpbmdTbGFzaCIsInN0ciIsImVuZHNXaXRoIiwic3Vic3RyIiwibGVuZ3RoIiwiQ29uZmlnIiwiZ2V0IiwiYXBwbGljYXRpb25JZCIsIm1vdW50IiwiY2FjaGVJbmZvIiwiQXBwQ2FjaGUiLCJjb25maWciLCJPYmplY3QiLCJrZXlzIiwiZm9yRWFjaCIsImtleSIsInNjaGVtYUNhY2hlIiwiU2NoZW1hQ2FjaGUiLCJjYWNoZUNvbnRyb2xsZXIiLCJzY2hlbWFDYWNoZVRUTCIsImVuYWJsZVNpbmdsZVNjaGVtYUNhY2hlIiwiZGF0YWJhc2UiLCJEYXRhYmFzZUNvbnRyb2xsZXIiLCJkYXRhYmFzZUNvbnRyb2xsZXIiLCJhZGFwdGVyIiwiZ2VuZXJhdGVTZXNzaW9uRXhwaXJlc0F0IiwiYmluZCIsImdlbmVyYXRlRW1haWxWZXJpZnlUb2tlbkV4cGlyZXNBdCIsInB1dCIsInNlcnZlckNvbmZpZ3VyYXRpb24iLCJ2YWxpZGF0ZSIsImFwcElkIiwic2V0dXBQYXNzd29yZFZhbGlkYXRvciIsInBhc3N3b3JkUG9saWN5IiwidmVyaWZ5VXNlckVtYWlscyIsInVzZXJDb250cm9sbGVyIiwiYXBwTmFtZSIsInB1YmxpY1NlcnZlclVSTCIsInJldm9rZVNlc3Npb25PblBhc3N3b3JkUmVzZXQiLCJleHBpcmVJbmFjdGl2ZVNlc3Npb25zIiwic2Vzc2lvbkxlbmd0aCIsIm1heExpbWl0IiwiZW1haWxWZXJpZnlUb2tlblZhbGlkaXR5RHVyYXRpb24iLCJhY2NvdW50TG9ja291dCIsIm1hc3RlcktleUlwcyIsIm1hc3RlcktleSIsInJlYWRPbmx5TWFzdGVyS2V5IiwiYWxsb3dIZWFkZXJzIiwiaWRlbXBvdGVuY3lPcHRpb25zIiwiZW1haWxWZXJpZnlUb2tlblJldXNlSWZWYWxpZCIsImZpbGVVcGxvYWQiLCJFcnJvciIsImVtYWlsQWRhcHRlciIsInZhbGlkYXRlRW1haWxDb25maWd1cmF0aW9uIiwidmFsaWRhdGVBY2NvdW50TG9ja291dFBvbGljeSIsInZhbGlkYXRlUGFzc3dvcmRQb2xpY3kiLCJ2YWxpZGF0ZUZpbGVVcGxvYWRPcHRpb25zIiwic3RhcnRzV2l0aCIsInZhbGlkYXRlU2Vzc2lvbkNvbmZpZ3VyYXRpb24iLCJ2YWxpZGF0ZU1hc3RlcktleUlwcyIsInZhbGlkYXRlTWF4TGltaXQiLCJ2YWxpZGF0ZUFsbG93SGVhZGVycyIsInZhbGlkYXRlSWRlbXBvdGVuY3lPcHRpb25zIiwidHRsIiwidW5kZWZpbmVkIiwiSWRlbXBvdGVuY3lPcHRpb25zIiwiZGVmYXVsdCIsImlzTmFOIiwicGF0aHMiLCJBcnJheSIsImR1cmF0aW9uIiwiTnVtYmVyIiwiaXNJbnRlZ2VyIiwidGhyZXNob2xkIiwidW5sb2NrT25QYXNzd29yZFJlc2V0IiwiQWNjb3VudExvY2tvdXRPcHRpb25zIiwibWF4UGFzc3dvcmRBZ2UiLCJyZXNldFRva2VuVmFsaWRpdHlEdXJhdGlvbiIsInZhbGlkYXRvclBhdHRlcm4iLCJSZWdFeHAiLCJ2YWxpZGF0b3JDYWxsYmFjayIsImRvTm90QWxsb3dVc2VybmFtZSIsIm1heFBhc3N3b3JkSGlzdG9yeSIsInJlc2V0VG9rZW5SZXVzZUlmVmFsaWQiLCJwYXR0ZXJuVmFsaWRhdG9yIiwidmFsdWUiLCJ0ZXN0IiwiZSIsIlJlZmVyZW5jZUVycm9yIiwiZW5hYmxlRm9yQW5vbnltb3VzVXNlciIsIkZpbGVVcGxvYWRPcHRpb25zIiwiZW5hYmxlRm9yUHVibGljIiwiZW5hYmxlRm9yQXV0aGVudGljYXRlZFVzZXIiLCJpcCIsIm5ldCIsImlzSVAiLCJfbW91bnQiLCJuZXdWYWx1ZSIsImluY2x1ZGVzIiwiaXNBcnJheSIsImhlYWRlciIsInRyaW0iLCJub3ciLCJEYXRlIiwiZ2V0VGltZSIsImdlbmVyYXRlUGFzc3dvcmRSZXNldFRva2VuRXhwaXJlc0F0IiwiaW52YWxpZExpbmtVUkwiLCJjdXN0b21QYWdlcyIsImludmFsaWRMaW5rIiwiaW52YWxpZFZlcmlmaWNhdGlvbkxpbmtVUkwiLCJpbnZhbGlkVmVyaWZpY2F0aW9uTGluayIsImxpbmtTZW5kU3VjY2Vzc1VSTCIsImxpbmtTZW5kU3VjY2VzcyIsImxpbmtTZW5kRmFpbFVSTCIsImxpbmtTZW5kRmFpbCIsInZlcmlmeUVtYWlsU3VjY2Vzc1VSTCIsInZlcmlmeUVtYWlsU3VjY2VzcyIsImNob29zZVBhc3N3b3JkVVJMIiwiY2hvb3NlUGFzc3dvcmQiLCJyZXF1ZXN0UmVzZXRQYXNzd29yZFVSTCIsInBhc3N3b3JkUmVzZXRTdWNjZXNzVVJMIiwicGFzc3dvcmRSZXNldFN1Y2Nlc3MiLCJwYXJzZUZyYW1lVVJMIiwidmVyaWZ5RW1haWxVUkwiLCJtb2R1bGUiLCJleHBvcnRzIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBSUE7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBS0E7Ozs7QUFiQTtBQUNBO0FBQ0E7QUFhQSxTQUFTQSxtQkFBVCxDQUE2QkMsR0FBN0IsRUFBa0M7QUFDaEMsTUFBSSxDQUFDQSxHQUFMLEVBQVU7QUFDUixXQUFPQSxHQUFQO0FBQ0Q7O0FBQ0QsTUFBSUEsR0FBRyxDQUFDQyxRQUFKLENBQWEsR0FBYixDQUFKLEVBQXVCO0FBQ3JCRCxJQUFBQSxHQUFHLEdBQUdBLEdBQUcsQ0FBQ0UsTUFBSixDQUFXLENBQVgsRUFBY0YsR0FBRyxDQUFDRyxNQUFKLEdBQWEsQ0FBM0IsQ0FBTjtBQUNEOztBQUNELFNBQU9ILEdBQVA7QUFDRDs7QUFFTSxNQUFNSSxNQUFOLENBQWE7QUFDbEIsU0FBT0MsR0FBUCxDQUFXQyxhQUFYLEVBQWtDQyxLQUFsQyxFQUFpRDtBQUMvQyxVQUFNQyxTQUFTLEdBQUdDLGVBQVNKLEdBQVQsQ0FBYUMsYUFBYixDQUFsQjs7QUFDQSxRQUFJLENBQUNFLFNBQUwsRUFBZ0I7QUFDZDtBQUNEOztBQUNELFVBQU1FLE1BQU0sR0FBRyxJQUFJTixNQUFKLEVBQWY7QUFDQU0sSUFBQUEsTUFBTSxDQUFDSixhQUFQLEdBQXVCQSxhQUF2QjtBQUNBSyxJQUFBQSxNQUFNLENBQUNDLElBQVAs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O0FBSUQ7O0FBRUQsTUFBSTBFLGtCQUFKLEdBQXlCO0FBQ3ZCLFdBQ0UsS0FBS0osV0FBTCxDQUFpQkssZUFBakIsSUFBcUMsR0FBRSxLQUFLM0UsZUFBZ0IsOEJBRDlEO0FBR0Q7O0FBRUQsTUFBSTRFLGVBQUosR0FBc0I7QUFDcEIsV0FBTyxLQUFLTixXQUFMLENBQWlCTyxZQUFqQixJQUFrQyxHQUFFLEtBQUs3RSxlQUFnQiwyQkFBaEU7QUFDRDs7QUFFRCxNQUFJOEUscUJBQUosR0FBNEI7QUFDMUIsV0FDRSxLQUFLUixXQUFMLENBQWlCUyxrQkFBakIsSUFDQyxHQUFFLEtBQUsvRSxlQUFnQixpQ0FGMUI7QUFJRDs7QUFFRCxNQUFJZ0YsaUJBQUosR0FBd0I7QUFDdEIsV0FBTyxLQUFLVixXQUFMLENBQWlCVyxjQUFqQixJQUFvQyxHQUFFLEtBQUtqRixlQUFnQix1QkFBbEU7QUFDRDs7QUFFRCxNQUFJa0YsdUJBQUosR0FBOEI7QUFDNUIsV0FBUSxHQUFFLEtBQUtsRixlQUFnQixTQUFRLEtBQUs5QixhQUFjLHlCQUExRDtBQUNEOztBQUVELE1BQUlpSCx1QkFBSixHQUE4QjtBQUM1QixXQUNFLEtBQUtiLFdBQUwsQ0FBaUJjLG9CQUFqQixJQUNDLEdBQUUsS0FBS3BGLGVBQWdCLG1DQUYxQjtBQUlEOztBQUVELE1BQUlxRixhQUFKLEdBQW9CO0FBQ2xCLFdBQU8sS0FBS2YsV0FBTCxDQUFpQmUsYUFBeEI7QUFDRDs7QUFFRCxNQUFJQyxjQUFKLEdBQXFCO0FBQ25CLFdBQVEsR0FBRSxLQUFLdEYsZUFBZ0IsU0FBUSxLQUFLOUIsYUFBYyxlQUExRDtBQUNEOztBQW5ZaUI7OztlQXNZTEYsTTs7QUFDZnVILE1BQU0sQ0FBQ0MsT0FBUCxHQUFpQnhILE1BQWpCIiwic291cmNlc0NvbnRlbnQiOlsiLy8gQSBDb25maWcgb2JqZWN0IHByb3ZpZGVzIGluZm9ybWF0aW9uIGFib3V0IGhvdyBhIHNwZWNpZmljIGFwcCBpc1xuLy8gY29uZmlndXJlZC5cbi8vIG1vdW50IGlzIHRoZSBVUkwgZm9yIHRoZSByb290IG9mIHRoZSBBUEk7IGluY2x1ZGVzIGh0dHAsIGRvbWFpbiwgZXRjLlxuXG5pbXBvcnQgQXBwQ2FjaGUgZnJvbSAnLi9jYWNoZSc7XG5pbXBvcnQgU2NoZW1hQ2FjaGUgZnJvbSAnLi9Db250cm9sbGVycy9TY2hlbWFDYWNoZSc7XG5pbXBvcnQgRGF0YWJhc2VDb250cm9sbGVyIGZyb20gJy4vQ29udHJvbGxlcnMvRGF0YWJhc2VDb250cm9sbGVyJztcbmltcG9ydCBuZXQgZnJvbSAnbmV0JztcbmltcG9ydCB7XG4gIElkZW1wb3RlbmN5T3B0aW9ucyxcbiAgRmlsZVVwbG9hZE9wdGlvbnMsXG4gIEFjY291bnRMb2Nrb3V0T3B0aW9ucyxcbn0gZnJvbSAnLi9PcHRpb25zL0RlZmluaXRpb25zJztcbmltcG9ydCB7IGlzQm9vbGVhbiB9IGZyb20gJ2xvZGFzaCc7XG5cbmZ1bmN0aW9uIHJlbW92ZVRyYWlsaW5nU2xhc2goc3RyKSB7XG4gIGlmICghc3RyKSB7XG4gICAgcmV0dXJuIHN0cjtcbiAgfVxuICBpZiAoc3RyLmVuZHNXaXRoKCcvJykpIHtcbiAgICBzdHIgPSBzdHIuc3Vic3RyKDAsIHN0ci5sZW5ndGggLSAxKTtcbiAgfVxuICByZXR1cm4gc3RyO1xufVxuXG5leHBvcnQgY2xhc3MgQ29uZmlnIHtcbiAgc3RhdGljIGdldChhcHBsaWNhdGlvbklkOiBzdHJpbmcsIG1vdW50OiBzdHJpbmcpIHtcbiAgICBjb25zdCBjYWNoZUluZm8gPSBBcHBDYWNoZS5nZXQoYXBwbGljYXRpb25JZCk7XG4gICAgaWYgKCFjYWNoZUluZm8pIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG4gICAgY29uc3QgY29uZmlnID0gbmV3IENvbmZpZygpO1xuICAgIGNvbmZpZy5hcHBsaWNhdGlvbklkID0gYXBwbGljYXRpb25JZDtcbiAgICBPYmplY3Qua2V5cyhjYWNoZUluZm8pLmZvckVhY2goa2V5ID0+IHtcbiAgICAgIGlmIChrZXkgPT0gJ2RhdGFiYXNlQ29udHJvbGxlcicpIHtcbiAgICAgICAgY29uc3Qgc2NoZW1hQ2FjaGUgPSBuZXcgU2NoZW1hQ2FjaGUoXG4gICAgICAgICAgY2FjaGVJbmZvLmNhY2hlQ29udHJvbGxlcixcbiAgICAgICAgICBjYWNoZUluZm8uc2NoZW1hQ2FjaGVUVEwsXG4gICAgICAgICAgY2FjaGVJbmZvLmVuYWJsZVNpbmdsZVNjaGVtYUNhY2hlXG4gICAgICAgICk7XG4gICAgICAgIGNvbmZpZy5kYXRhYmFzZSA9IG5ldyBEYXRhYmFzZUNvbnRyb2xsZXIoY2FjaGVJbmZvLmRhdGFiYXNlQ29udHJvbGxlci5hZGFwdGVyLCBzY2hlbWFDYWNoZSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb25maWdba2V5XSA9IGNhY2hlSW5mb1trZXldO1xuICAgICAgfVxuICAgIH0pO1xuICAgIGNvbmZpZy5tb3VudCA9IHJlbW92ZVRyYWlsaW5nU2xhc2gobW91bnQpO1xuICAgIGNvbmZpZy5nZW5lcmF0ZVNlc3Npb25FeHBpcmVzQXQgPSBjb25maWcuZ2VuZXJhdGVTZXNzaW9uRXhwaXJlc0F0LmJpbmQoY29uZmlnKTtcbiAgICBjb25maWcuZ2VuZXJhdGVFbWFpbFZlcmlmeVRva2VuRXhwaXJlc0F0ID0gY29uZmlnLmdlbmVyYXRlRW1haWxWZXJpZnlUb2tlbkV4cGlyZXNBdC5iaW5kKFxuICAgICAgY29uZmlnXG4gICAgKTtcbiAgICByZXR1cm4gY29uZmlnO1xuICB9XG5cbiAgc3RhdGljIHB1dChzZXJ2ZXJDb25maWd1cmF0aW9uKSB7XG4gICAgQ29uZmlnLnZhbGlkYXRlKHNlcnZlckNvbmZpZ3VyYXRpb24pO1xuICAgIEFwcENhY2hlLnB1dChzZXJ2ZXJDb25maWd1cmF0aW9uLmFwcElkLCBzZXJ2ZXJDb25maWd1cmF0aW9uKTtcbiAgICBDb25maWcuc2V0dXBQYXNzd29yZFZhbGlkYXRvcihzZXJ2ZXJDb25maWd1cmF0aW9uLnBhc3N3b3JkUG9saWN5KTtcbiAgICByZXR1cm4gc2VydmVyQ29uZmlndXJhdGlvbjtcbiAgfVxuXG4gIHN0YXRpYyB2YWxpZGF0ZSh7XG4gICAgdmVyaWZ5VXNlckVtYWlscyxcbiAgICB1c2VyQ29udHJvbGxlcixcbiAgICBhcHBOYW1lLFxuICAgIHB1YmxpY1NlcnZlclVSTCxcbiAgICByZXZva2VTZXNzaW9uT25QYXNzd29yZFJlc2V0LFxuICAgIGV4cGlyZUluYWN0aXZlU2Vzc2lvbnMsXG4gICAgc2Vzc2lvbkxlbmd0aCxcbiAgICBtYXhMaW1pdCxcbiAgICBlbWFpbFZlcmlmeVRva2VuVmFsaWRpdHlEdXJhdGlvbixcbiAgICBhY2NvdW50TG9ja291dCxcbiAgICBwYXNzd29yZFBvbGljeSxcbiAgICBtYXN0ZXJLZXlJcHMsXG4gICAgbWFzdGVyS2V5LFxuICAgIHJlYWRPbmx5TWFzdGVyS2V5LFxuICAgIGFsbG93SGVhZGVycyxcbiAgICBpZGVtcG90ZW5jeU9wdGlvbnMsXG4gICAgZW1haWxWZXJpZnlUb2tlblJldXNlSWZWYWxpZCxcbiAgICBmaWxlVXBsb2FkLFxuICB9KSB7XG4gICAgaWYgKG1hc3RlcktleSA9PT0gcmVhZE9ubHlNYXN0ZXJLZXkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignbWFzdGVyS2V5IGFuZCByZWFkT25seU1hc3RlcktleSBzaG91bGQgYmUgZGlmZmVyZW50Jyk7XG4gICAgfVxuXG4gICAgY29uc3QgZW1haWxBZGFwdGVyID0gdXNlckNvbnRyb2xsZXIuYWRhcHRlcjtcbiAgICBpZiAodmVyaWZ5VXNlckVtYWlscykge1xuICAgICAgdGhpcy52YWxpZGF0ZUVtYWlsQ29uZmlndXJhdGlvbih7XG4gICAgICAgIGVtYWlsQWRhcHRlcixcbiAgICAgICAgYXBwTmFtZSxcbiAgICAgICAgcHVibGljU2VydmVyVVJMLFxuICAgICAgICBlbWFpbFZlcmlmeVRva2VuVmFsaWRpdHlEdXJhdGlvbixcbiAgICAgICAgZW1haWxWZXJpZnlUb2tlblJldXNlSWZWYWxpZCxcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHRoaXMudmFsaWRhdGVBY2NvdW50TG9ja291dFBvbGljeShhY2NvdW50TG9ja291dCk7XG4gICAgdGhpcy52YWxpZGF0ZVBhc3N3b3JkUG9saWN5KHBhc3N3b3JkUG9saWN5KTtcbiAgICB0aGlzLnZhbGlkYXRlRmlsZVVwbG9hZE9wdGlvbnMoZmlsZVVwbG9hZCk7XG5cbiAgICBpZiAodHlwZW9mIHJldm9rZVNlc3Npb25PblBhc3N3b3JkUmVzZXQgIT09ICdib29sZWFuJykge1xuICAgICAgdGhyb3cgJ3Jldm9rZVNlc3Npb25PblBhc3N3b3JkUmVzZXQgbXVzdCBiZSBhIGJvb2xlYW4gdmFsdWUnO1xuICAgIH1cblxuICAgIGlmIChwdWJsaWNTZXJ2ZXJVUkwpIHtcbiAgICAgIGlmICghcHVibGljU2VydmVyVVJMLnN0YXJ0c1dpdGgoJ2h0dHA6Ly8nKSAmJiAhcHVibGljU2VydmVyVVJMLnN0YXJ0c1dpdGgoJ2h0dHBzOi8vJykpIHtcbiAgICAgICAgdGhyb3cgJ3B1YmxpY1NlcnZlclVSTCBzaG91bGQgYmUgYSB2YWxpZCBIVFRQUyBVUkwgc3RhcnRpbmcgd2l0aCBodHRwczovLyc7XG4gICAgICB9XG4gICAgfVxuICAgIHRoaXMudmFsaWRhdGVTZXNzaW9uQ29uZmlndXJhdGlvbihzZXNzaW9uTGVuZ3RoLCBleHBpcmVJbmFjdGl2ZVNlc3Npb25zKTtcbiAgICB0aGlzLnZhbGlkYXRlTWFzdGVyS2V5SXBzKG1hc3RlcktleUlwcyk7XG4gICAgdGhpcy52YWxpZGF0ZU1heExpbWl0KG1heExpbWl0KTtcbiAgICB0aGlzLnZhbGlkYXRlQWxsb3dIZWFkZXJzKGFsbG93SGVhZGVycyk7XG4gICAgdGhpcy52YWxpZGF0ZUlkZW1wb3RlbmN5T3B0aW9ucyhpZGVtcG90ZW5jeU9wdGlvbnMpO1xuICB9XG5cbiAgc3RhdGljIHZhbGlkYXRlSWRlbXBvdGVuY3lPcHRpb25zKGlkZW1wb3RlbmN5T3B0aW9ucykge1xuICAgIGlmICghaWRlbXBvdGVuY3lPcHRpb25zKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmIChpZGVtcG90ZW5jeU9wdGlvbnMudHRsID09PSB1bmRlZmluZWQpIHtcbiAgICAgIGlkZW1wb3RlbmN5T3B0aW9ucy50dGwgPSBJZGVtcG90ZW5jeU9wdGlvbnMudHRsLmRlZmF1bHQ7XG4gICAgfSBlbHNlIGlmICghaXNOYU4oaWRlbXBvdGVuY3lPcHRpb25zLnR0bCkgJiYgaWRlbXBvdGVuY3lPcHRpb25zLnR0bCA8PSAwKSB7XG4gICAgICB0aHJvdyAnaWRlbXBvdGVuY3kgVFRMIHZhbHVlIG11c3QgYmUgZ3JlYXRlciB0aGFuIDAgc2Vjb25kcyc7XG4gICAgfSBlbHNlIGlmIChpc05hTihpZGVtcG90ZW5jeU9wdGlvbnMudHRsKSkge1xuICAgICAgdGhyb3cgJ2lkZW1wb3RlbmN5IFRUTCB2YWx1ZSBtdXN0IGJlIGEgbnVtYmVyJztcbiAgICB9XG4gICAgaWYgKCFpZGVtcG90ZW5jeU9wdGlvbnMucGF0aHMpIHtcbiAgICAgIGlkZW1wb3RlbmN5T3B0aW9ucy5wYXRocyA9IElkZW1wb3RlbmN5T3B0aW9ucy5wYXRocy5kZWZhdWx0O1xuICAgIH0gZWxzZSBpZiAoIShpZGVtcG90ZW5jeU9wdGlvbnMucGF0aHMgaW5zdGFuY2VvZiBBcnJheSkpIHtcbiAgICAgIHRocm93ICdpZGVtcG90ZW5jeSBwYXRocyBtdXN0IGJlIG9mIGFuIGFycmF5IG9mIHN0cmluZ3MnO1xuICAgIH1cbiAgfVxuXG4gIHN0YXRpYyB2YWxpZGF0ZUFjY291bnRMb2Nrb3V0UG9saWN5KGFjY291bnRMb2Nrb3V0KSB7XG4gICAgaWYgKGFjY291bnRMb2Nrb3V0KSB7XG4gICAgICBpZiAoXG4gICAgICAgIHR5cGVvZiBhY2NvdW50TG9ja291dC5kdXJhdGlvbiAhPT0gJ251bWJlcicgfHxcbiAgICAgICAgYWNjb3VudExvY2tvdXQuZHVyYXRpb24gPD0gMCB8fFxuICAgICAgICBhY2NvdW50TG9ja291dC5kdXJhdGlvbiA+IDk5OTk5XG4gICAgICApIHtcbiAgICAgICAgdGhyb3cgJ0FjY291bnQgbG9ja291dCBkdXJhdGlvbiBzaG91bGQgYmUgZ3JlYXRlciB0aGFuIDAgYW5kIGxlc3MgdGhhbiAxMDAwMDAnO1xuICAgICAgfVxuXG4gICAgICBpZiAoXG4gICAgICAgICFOdW1iZXIuaXNJbnRlZ2VyKGFjY291bnRMb2Nrb3V0LnRocmVzaG9sZCkgfHxcbiAgICAgICAgYWNjb3VudExvY2tvdXQudGhyZXNob2xkIDwgMSB8fFxuICAgICAgICBhY2NvdW50TG9ja291dC50aHJlc2hvbGQgPiA5OTlcbiAgICAgICkge1xuICAgICAgICB0aHJvdyAnQWNjb3VudCBsb2Nrb3V0IHRocmVzaG9sZCBzaG91bGQgYmUgYW4gaW50ZWdlciBncmVhdGVyIHRoYW4gMCBhbmQgbGVzcyB0aGFuIDEwMDAnO1xuICAgICAgfVxuXG4gICAgICBpZiAoYWNjb3VudExvY2tvdXQudW5sb2NrT25QYXNzd29yZFJlc2V0ID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgYWNjb3VudExvY2tvdXQudW5sb2NrT25QYXNzd29yZFJlc2V0ID0gQWNjb3VudExvY2tvdXRPcHRpb25zLnVubG9ja09uUGFzc3dvcmRSZXNldC5kZWZhdWx0O1xuICAgICAgfSBlbHNlIGlmICghaXNCb29sZWFuKGFjY291bnRMb2Nrb3V0LnVubG9ja09uUGFzc3dvcmRSZXNldCkpIHtcbiAgICAgICAgdGhyb3cgJ1BhcnNlIFNlcnZlciBvcHRpb24gYWNjb3VudExvY2tvdXQudW5sb2NrT25QYXNzd29yZFJlc2V0IG11c3QgYmUgYSBib29sZWFuLic7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgc3RhdGljIHZhbGlkYXRlUGFzc3dvcmRQb2xpY3kocGFzc3dvcmRQb2xpY3kpIHtcbiAgICBpZiAocGFzc3dvcmRQb2xpY3kpIHtcbiAgICAgIGlmIChcbiAgICAgICAgcGFzc3dvcmRQb2xpY3kubWF4UGFzc3dvcmRBZ2UgIT09IHVuZGVmaW5lZCAmJlxuICAgICAgICAodHlwZW9mIHBhc3N3b3JkUG9saWN5Lm1heFBhc3N3b3JkQWdlICE9PSAnbnVtYmVyJyB8fCBwYXNzd29yZFBvbGljeS5tYXhQYXNzd29yZEFnZSA8IDApXG4gICAgICApIHtcbiAgICAgICAgdGhyb3cgJ3Bhc3N3b3JkUG9saWN5Lm1heFBhc3N3b3JkQWdlIG11c3QgYmUgYSBwb3NpdGl2ZSBudW1iZXInO1xuICAgICAgfVxuXG4gICAgICBpZiAoXG4gICAgICAgIHBhc3N3b3JkUG9saWN5LnJlc2V0VG9rZW5WYWxpZGl0eUR1cmF0aW9uICE9PSB1bmRlZmluZWQgJiZcbiAgICAgICAgKHR5cGVvZiBwYXNzd29yZFBvbGljeS5yZXNldFRva2VuVmFsaWRpdHlEdXJhdGlvbiAhPT0gJ251bWJlcicgfHxcbiAgICAgICAgICBwYXNzd29yZFBvbGljeS5yZXNldFRva2VuVmFsaWRpdHlEdXJhdGlvbiA8PSAwKVxuICAgICAgKSB7XG4gICAgICAgIHRocm93ICdwYXNzd29yZFBvbGljeS5yZXNldFRva2VuVmFsaWRpdHlEdXJhdGlvbiBtdXN0IGJlIGEgcG9zaXRpdmUgbnVtYmVyJztcbiAgICAgIH1cblxuICAgICAgaWYgKHBhc3N3b3JkUG9saWN5LnZhbGlkYXRvclBhdHRlcm4pIHtcbiAgICAgICAgaWYgKHR5cGVvZiBwYXNzd29yZFBvbGljeS52YWxpZGF0b3JQYXR0ZXJuID09PSAnc3RyaW5nJykge1xuICAgICAgICAgIHBhc3N3b3JkUG9saWN5LnZhbGlkYXRvclBhdHRlcm4gPSBuZXcgUmVnRXhwKHBhc3N3b3JkUG9saWN5LnZhbGlkYXRvclBhdHRlcm4pO1xuICAgICAgICB9IGVsc2UgaWYgKCEocGFzc3dvcmRQb2xpY3kudmFsaWRhdG9yUGF0dGVybiBpbnN0YW5jZW9mIFJlZ0V4cCkpIHtcbiAgICAgICAgICB0aHJvdyAncGFzc3dvcmRQb2xpY3kudmFsaWRhdG9yUGF0dGVybiBtdXN0IGJlIGEgcmVnZXggc3RyaW5nIG9yIFJlZ0V4cCBvYmplY3QuJztcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoXG4gICAgICAgIHBhc3N3b3JkUG9saWN5LnZhbGlkYXRvckNhbGxiYWNrICYmXG4gICAgICAgIHR5cGVvZiBwYXNzd29yZFBvbGljeS52YWxpZGF0b3JDYWxsYmFjayAhPT0gJ2Z1bmN0aW9uJ1xuICAgICAgKSB7XG4gICAgICAgIHRocm93ICdwYXNzd29yZFBvbGljeS52YWxpZGF0b3JDYWxsYmFjayBtdXN0IGJlIGEgZnVuY3Rpb24uJztcbiAgICAgIH1cblxuICAgICAgaWYgKFxuICAgICAgICBwYXNzd29yZFBvbGljeS5kb05vdEFsbG93VXNlcm5hbWUgJiZcbiAgICAgICAgdHlwZW9mIHBhc3N3b3JkUG9saWN5LmRvTm90QWxsb3dVc2VybmFtZSAhPT0gJ2Jvb2xlYW4nXG4gICAgICApIHtcbiAgICAgICAgdGhyb3cgJ3Bhc3N3b3JkUG9saWN5LmRvTm90QWxsb3dVc2VybmFtZSBtdXN0IGJlIGEgYm9vbGVhbiB2YWx1ZS4nO1xuICAgICAgfVxuXG4gICAgICBpZiAoXG4gICAgICAgIHBhc3N3b3JkUG9saWN5Lm1heFBhc3N3b3JkSGlzdG9yeSAmJlxuICAgICAgICAoIU51bWJlci5pc0ludGVnZXIocGFzc3dvcmRQb2xpY3kubWF4UGFzc3dvcmRIaXN0b3J5KSB8fFxuICAgICAgICAgIHBhc3N3b3JkUG9saWN5Lm1heFBhc3N3b3JkSGlzdG9yeSA8PSAwIHx8XG4gICAgICAgICAgcGFzc3dvcmRQb2xpY3kubWF4UGFzc3dvcmRIaXN0b3J5ID4gMjApXG4gICAgICApIHtcbiAgICAgICAgdGhyb3cgJ3Bhc3N3b3JkUG9saWN5Lm1heFBhc3N3b3JkSGlzdG9yeSBtdXN0IGJlIGFuIGludGVnZXIgcmFuZ2luZyAwIC0gMjAnO1xuICAgICAgfVxuXG4gICAgICBpZiAoXG4gICAgICAgIHBhc3N3b3JkUG9saWN5LnJlc2V0VG9rZW5SZXVzZUlmVmFsaWQgJiZcbiAgICAgICAgdHlwZW9mIHBhc3N3b3JkUG9saWN5LnJlc2V0VG9rZW5SZXVzZUlmVmFsaWQgIT09ICdib29sZWFuJ1xuICAgICAgKSB7XG4gICAgICAgIHRocm93ICdyZXNldFRva2VuUmV1c2VJZlZhbGlkIG11c3QgYmUgYSBib29sZWFuIHZhbHVlJztcbiAgICAgIH1cbiAgICAgIGlmIChwYXNzd29yZFBvbGljeS5yZXNldFRva2VuUmV1c2VJZlZhbGlkICYmICFwYXNzd29yZFBvbGljeS5yZXNldFRva2VuVmFsaWRpdHlEdXJhdGlvbikge1xuICAgICAgICB0aHJvdyAnWW91IGNhbm5vdCB1c2UgcmVzZXRUb2tlblJldXNlSWZWYWxpZCB3aXRob3V0IHJlc2V0VG9rZW5WYWxpZGl0eUR1cmF0aW9uJztcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvLyBpZiB0aGUgcGFzc3dvcmRQb2xpY3kudmFsaWRhdG9yUGF0dGVybiBpcyBjb25maWd1cmVkIHRoZW4gc2V0dXAgYSBjYWxsYmFjayB0byBwcm9jZXNzIHRoZSBwYXR0ZXJuXG4gIHN0YXRpYyBzZXR1cFBhc3N3b3JkVmFsaWRhdG9yKHBhc3N3b3JkUG9saWN5KSB7XG4gICAgaWYgKHBhc3N3b3JkUG9saWN5ICYmIHBhc3N3b3JkUG9saWN5LnZhbGlkYXRvclBhdHRlcm4pIHtcbiAgICAgIHBhc3N3b3JkUG9saWN5LnBhdHRlcm5WYWxpZGF0b3IgPSB2YWx1ZSA9PiB7XG4gICAgICAgIHJldHVybiBwYXNzd29yZFBvbGljeS52YWxpZGF0b3JQYXR0ZXJuLnRlc3QodmFsdWUpO1xuICAgICAgfTtcbiAgICB9XG4gIH1cblxuICBzdGF0aWMgdmFsaWRhdGVFbWFpbENvbmZpZ3VyYXRpb24oe1xuICAgIGVtYWlsQWRhcHRlcixcbiAgICBhcHBOYW1lLFxuICAgIHB1YmxpY1NlcnZlclVSTCxcbiAgICBlbWFpbFZlcmlmeVRva2VuVmFsaWRpdHlEdXJhdGlvbixcbiAgICBlbWFpbFZlcmlmeVRva2VuUmV1c2VJZlZhbGlkLFxuICB9KSB7XG4gICAgaWYgKCFlbWFpbEFkYXB0ZXIpIHtcbiAgICAgIHRocm93ICdBbiBlbWFpbEFkYXB0ZXIgaXMgcmVxdWlyZWQgZm9yIGUtbWFpbCB2ZXJpZmljYXRpb24gYW5kIHBhc3N3b3JkIHJlc2V0cy4nO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGFwcE5hbWUgIT09ICdzdHJpbmcnKSB7XG4gICAgICB0aHJvdyAnQW4gYXBwIG5hbWUgaXMgcmVxdWlyZWQgZm9yIGUtbWFpbCB2ZXJpZmljYXRpb24gYW5kIHBhc3N3b3JkIHJlc2V0cy4nO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIHB1YmxpY1NlcnZlclVSTCAhPT0gJ3N0cmluZycpIHtcbiAgICAgIHRocm93ICdBIHB1YmxpYyBzZXJ2ZXIgdXJsIGlzIHJlcXVpcmVkIGZvciBlLW1haWwgdmVyaWZpY2F0aW9uIGFuZCBwYXNzd29yZCByZXNldHMuJztcbiAgICB9XG4gICAgaWYgKGVtYWlsVmVyaWZ5VG9rZW5WYWxpZGl0eUR1cmF0aW9uKSB7XG4gICAgICBpZiAoaXNOYU4oZW1haWxWZXJpZnlUb2tlblZhbGlkaXR5RHVyYXRpb24pKSB7XG4gICAgICAgIHRocm93ICdFbWFpbCB2ZXJpZnkgdG9rZW4gdmFsaWRpdHkgZHVyYXRpb24gbXVzdCBiZSBhIHZhbGlkIG51bWJlci4nO1xuICAgICAgfSBlbHNlIGlmIChlbWFpbFZlcmlmeVRva2VuVmFsaWRpdHlEdXJhdGlvbiA8PSAwKSB7XG4gICAgICAgIHRocm93ICdFbWFpbCB2ZXJpZnkgdG9rZW4gdmFsaWRpdHkgZHVyYXRpb24gbXVzdCBiZSBhIHZhbHVlIGdyZWF0ZXIgdGhhbiAwLic7XG4gICAgICB9XG4gICAgfVxuICAgIGlmIChlbWFpbFZlcmlmeVRva2VuUmV1c2VJZlZhbGlkICYmIHR5cGVvZiBlbWFpbFZlcmlmeVRva2VuUmV1c2VJZlZhbGlkICE9PSAnYm9vbGVhbicpIHtcbiAgICAgIHRocm93ICdlbWFpbFZlcmlmeVRva2VuUmV1c2VJZlZhbGlkIG11c3QgYmUgYSBib29sZWFuIHZhbHVlJztcbiAgICB9XG4gICAgaWYgKGVtYWlsVmVyaWZ5VG9rZW5SZXVzZUlmVmFsaWQgJiYgIWVtYWlsVmVyaWZ5VG9rZW5WYWxpZGl0eUR1cmF0aW9uKSB7XG4gICAgICB0aHJvdyAnWW91IGNhbm5vdCB1c2UgZW1haWxWZXJpZnlUb2tlblJldXNlSWZWYWxpZCB3aXRob3V0IGVtYWlsVmVyaWZ5VG9rZW5WYWxpZGl0eUR1cmF0aW9uJztcbiAgICB9XG4gIH1cblxuICBzdGF0aWMgdmFsaWRhdGVGaWxlVXBsb2FkT3B0aW9ucyhmaWxlVXBsb2FkKSB7XG4gICAgdHJ5IHtcbiAgICAgIGlmIChmaWxlVXBsb2FkID09IG51bGwgfHwgdHlwZW9mIGZpbGVVcGxvYWQgIT09ICdvYmplY3QnIHx8IGZpbGVVcGxvYWQgaW5zdGFuY2VvZiBBcnJheSkge1xuICAgICAgICB0aHJvdyAnZmlsZVVwbG9hZCBtdXN0IGJlIGFuIG9iamVjdCB2YWx1ZS4nO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGlmIChlIGluc3RhbmNlb2YgUmVmZXJlbmNlRXJyb3IpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgdGhyb3cgZTtcbiAgICB9XG4gICAgaWYgKGZpbGVVcGxvYWQuZW5hYmxlRm9yQW5vbnltb3VzVXNlciA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICBmaWxlVXBsb2FkLmVuYWJsZUZvckFub255bW91c1VzZXIgPSBGaWxlVXBsb2FkT3B0aW9ucy5lbmFibGVGb3JBbm9ueW1vdXNVc2VyLmRlZmF1bHQ7XG4gICAgfSBlbHNlIGlmICh0eXBlb2YgZmlsZVVwbG9hZC5lbmFibGVGb3JBbm9ueW1vdXNVc2VyICE9PSAnYm9vbGVhbicpIHtcbiAgICAgIHRocm93ICdmaWxlVXBsb2FkLmVuYWJsZUZvckFub255bW91c1VzZXIgbXVzdCBiZSBhIGJvb2xlYW4gdmFsdWUuJztcbiAgICB9XG4gICAgaWYgKGZpbGVVcGxvYWQuZW5hYmxlRm9yUHVibGljID09PSB1bmRlZmluZWQpIHtcbiAgICAgIGZpbGVVcGxvYWQuZW5hYmxlRm9yUHVibGljID0gRmlsZVVwbG9hZE9wdGlvbnMuZW5hYmxlRm9yUHVibGljLmRlZmF1bHQ7XG4gICAgfSBlbHNlIGlmICh0eXBlb2YgZmlsZVVwbG9hZC5lbmFibGVGb3JQdWJsaWMgIT09ICdib29sZWFuJykge1xuICAgICAgdGhyb3cgJ2ZpbGVVcGxvYWQuZW5hYmxlRm9yUHVibGljIG11c3QgYmUgYSBib29sZWFuIHZhbHVlLic7XG4gICAgfVxuICAgIGlmIChmaWxlVXBsb2FkLmVuYWJsZUZvckF1dGhlbnRpY2F0ZWRVc2VyID09PSB1bmRlZmluZWQpIHtcbiAgICAgIGZpbGVVcGxvYWQuZW5hYmxlRm9yQXV0aGVudGljYXRlZFVzZXIgPSBGaWxlVXBsb2FkT3B0aW9ucy5lbmFibGVGb3JBdXRoZW50aWNhdGVkVXNlci5kZWZhdWx0O1xuICAgIH0gZWxzZSBpZiAodHlwZW9mIGZpbGVVcGxvYWQuZW5hYmxlRm9yQXV0aGVudGljYXRlZFVzZXIgIT09ICdib29sZWFuJykge1xuICAgICAgdGhyb3cgJ2ZpbGVVcGxvYWQuZW5hYmxlRm9yQXV0aGVudGljYXRlZFVzZXIgbXVzdCBiZSBhIGJvb2xlYW4gdmFsdWUuJztcbiAgICB9XG4gIH1cblxuICBzdGF0aWMgdmFsaWRhdGVNYXN0ZXJLZXlJcHMobWFzdGVyS2V5SXBzKSB7XG4gICAgZm9yIChjb25zdCBpcCBvZiBtYXN0ZXJLZXlJcHMpIHtcbiAgICAgIGlmICghbmV0LmlzSVAoaXApKSB7XG4gICAgICAgIHRocm93IGBJbnZhbGlkIGlwIGluIG1hc3RlcktleUlwczogJHtpcH1gO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIGdldCBtb3VudCgpIHtcbiAgICB2YXIgbW91bnQgPSB0aGlzLl9tb3VudDtcbiAgICBpZiAodGhpcy5wdWJsaWNTZXJ2ZXJVUkwpIHtcbiAgICAgIG1vdW50ID0gdGhpcy5wdWJsaWNTZXJ2ZXJVUkw7XG4gICAgfVxuICAgIHJldHVybiBtb3VudDtcbiAgfVxuXG4gIHNldCBtb3VudChuZXdWYWx1ZSkge1xuICAgIHRoaXMuX21vdW50ID0gbmV3VmFsdWU7XG4gIH1cblxuICBzdGF0aWMgdmFsaWRhdGVTZXNzaW9uQ29uZmlndXJhdGlvbihzZXNzaW9uTGVuZ3RoLCBleHBpcmVJbmFjdGl2ZVNlc3Npb25zKSB7XG4gICAgaWYgKGV4cGlyZUluYWN0aXZlU2Vzc2lvbnMpIHtcbiAgICAgIGlmIChpc05hTihzZXNzaW9uTGVuZ3RoKSkge1xuICAgICAgICB0aHJvdyAnU2Vzc2lvbiBsZW5ndGggbXVzdCBiZSBhIHZhbGlkIG51bWJlci4nO1xuICAgICAgfSBlbHNlIGlmIChzZXNzaW9uTGVuZ3RoIDw9IDApIHtcbiAgICAgICAgdGhyb3cgJ1Nlc3Npb24gbGVuZ3RoIG11c3QgYmUgYSB2YWx1ZSBncmVhdGVyIHRoYW4gMC4nO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIHN0YXRpYyB2YWxpZGF0ZU1heExpbWl0KG1heExpbWl0KSB7XG4gICAgaWYgKG1heExpbWl0IDw9IDApIHtcbiAgICAgIHRocm93ICdNYXggbGltaXQgbXVzdCBiZSBhIHZhbHVlIGdyZWF0ZXIgdGhhbiAwLic7XG4gICAgfVxuICB9XG5cbiAgc3RhdGljIHZhbGlkYXRlQWxsb3dIZWFkZXJzKGFsbG93SGVhZGVycykge1xuICAgIGlmICghW251bGwsIHVuZGVmaW5lZF0uaW5jbHVkZXMoYWxsb3dIZWFkZXJzKSkge1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkoYWxsb3dIZWFkZXJzKSkge1xuICAgICAgICBhbGxvd0hlYWRlcnMuZm9yRWFjaChoZWFkZXIgPT4ge1xuICAgICAgICAgIGlmICh0eXBlb2YgaGVhZGVyICE9PSAnc3RyaW5nJykge1xuICAgICAgICAgICAgdGhyb3cgJ0FsbG93IGhlYWRlcnMgbXVzdCBvbmx5IGNvbnRhaW4gc3RyaW5ncyc7XG4gICAgICAgICAgfSBlbHNlIGlmICghaGVhZGVyLnRyaW0oKS5sZW5ndGgpIHtcbiAgICAgICAgICAgIHRocm93ICdBbGxvdyBoZWFkZXJzIG11c3Qgbm90IGNvbnRhaW4gZW1wdHkgc3RyaW5ncyc7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRocm93ICdBbGxvdyBoZWFkZXJzIG11c3QgYmUgYW4gYXJyYXknO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIGdlbmVyYXRlRW1haWxWZXJpZnlUb2tlbkV4cGlyZXNBdCgpIHtcbiAgICBpZiAoIXRoaXMudmVyaWZ5VXNlckVtYWlscyB8fCAhdGhpcy5lbWFpbFZlcmlmeVRva2VuVmFsaWRpdHlEdXJhdGlvbikge1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG4gICAgdmFyIG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgcmV0dXJuIG5ldyBEYXRlKG5vdy5nZXRUaW1lKCkgKyB0aGlzLmVtYWlsVmVyaWZ5VG9rZW5WYWxpZGl0eUR1cmF0aW9uICogMTAwMCk7XG4gIH1cblxuICBnZW5lcmF0ZVBhc3N3b3JkUmVzZXRUb2tlbkV4cGlyZXNBdCgpIHtcbiAgICBpZiAoIXRoaXMucGFzc3dvcmRQb2xpY3kgfHwgIXRoaXMucGFzc3dvcmRQb2xpY3kucmVzZXRUb2tlblZhbGlkaXR5RHVyYXRpb24pIHtcbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XG4gICAgcmV0dXJuIG5ldyBEYXRlKG5vdy5nZXRUaW1lKCkgKyB0aGlzLnBhc3N3b3JkUG9saWN5LnJlc2V0VG9rZW5WYWxpZGl0eUR1cmF0aW9uICogMTAwMCk7XG4gIH1cblxuICBnZW5lcmF0ZVNlc3Npb25FeHBpcmVzQXQoKSB7XG4gICAgaWYgKCF0aGlzLmV4cGlyZUluYWN0aXZlU2Vzc2lvbnMpIHtcbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuICAgIHZhciBub3cgPSBuZXcgRGF0ZSgpO1xuICAgIHJldHVybiBuZXcgRGF0ZShub3cuZ2V0VGltZSgpICsgdGhpcy5zZXNzaW9uTGVuZ3RoICogMTAwMCk7XG4gIH1cblxuICBnZXQgaW52YWxpZExpbmtVUkwoKSB7XG4gICAgcmV0dXJuIHRoaXMuY3VzdG9tUGFnZXMuaW52YWxpZExpbmsgfHwgYCR7dGhpcy5wdWJsaWNTZXJ2ZXJVUkx9L2FwcHMvaW52YWxpZF9saW5rLmh0bWxgO1xuICB9XG5cbiAgZ2V0IGludmFsaWRWZXJpZmljYXRpb25MaW5rVVJMKCkge1xuICAgIHJldHVybiAoXG4gICAgICB0aGlzLmN1c3RvbVBhZ2VzLmludmFsaWRWZXJpZmljYXRpb25MaW5rIHx8XG4gICAgICBgJHt0aGlzLnB1YmxpY1NlcnZlclVSTH0vYXBwcy9pbnZhbGlkX3ZlcmlmaWNhdGlvbl9saW5rLmh0bWxgXG4gICAgKTtcbiAgfVxuXG4gIGdldCBsaW5rU2VuZFN1Y2Nlc3NVUkwoKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIHRoaXMuY3VzdG9tUGFnZXMubGlua1NlbmRTdWNjZXNzIHx8IGAke3RoaXMucHVibGljU2VydmVyVVJMfS9hcHBzL2xpbmtfc2VuZF9zdWNjZXNzLmh0bWxgXG4gICAgKTtcbiAgfVxuXG4gIGdldCBsaW5rU2VuZEZhaWxVUkwoKSB7XG4gICAgcmV0dXJuIHRoaXMuY3VzdG9tUGFnZXMubGlua1NlbmRGYWlsIHx8IGAke3RoaXMucHVibGljU2VydmVyVVJMfS9hcHBzL2xpbmtfc2VuZF9mYWlsLmh0bWxgO1xuICB9XG5cbiAgZ2V0IHZlcmlmeUVtYWlsU3VjY2Vzc1VSTCgpIHtcbiAgICByZXR1cm4gKFxuICAgICAgdGhpcy5jdXN0b21QYWdlcy52ZXJpZnlFbWFpbFN1Y2Nlc3MgfHxcbiAgICAgIGAke3RoaXMucHVibGljU2VydmVyVVJMfS9hcHBzL3ZlcmlmeV9lbWFpbF9zdWNjZXNzLmh0bWxgXG4gICAgKTtcbiAgfVxuXG4gIGdldCBjaG9vc2VQYXNzd29yZFVSTCgpIHtcbiAgICByZXR1cm4gdGhpcy5jdXN0b21QYWdlcy5jaG9vc2VQYXNzd29yZCB8fCBgJHt0aGlzLnB1YmxpY1NlcnZlclVSTH0vYXBwcy9jaG9vc2VfcGFzc3dvcmRgO1xuICB9XG5cbiAgZ2V0IHJlcXVlc3RSZXNldFBhc3N3b3JkVVJMKCkge1xuICAgIHJldHVybiBgJHt0aGlzLnB1YmxpY1NlcnZlclVSTH0vYXBwcy8ke3RoaXMuYXBwbGljYXRpb25JZH0vcmVxdWVzdF9wYXNzd29yZF9yZXNldGA7XG4gIH1cblxuICBnZXQgcGFzc3dvcmRSZXNldFN1Y2Nlc3NVUkwoKSB7XG4gICAgcmV0dXJuIChcbiAgICAgIHRoaXMuY3VzdG9tUGFnZXMucGFzc3dvcmRSZXNldFN1Y2Nlc3MgfHxcbiAgICAgIGAke3RoaXMucHVibGljU2VydmVyVVJMfS9hcHBzL3Bhc3N3b3JkX3Jlc2V0X3N1Y2Nlc3MuaHRtbGBcbiAgICApO1xuICB9XG5cbiAgZ2V0IHBhcnNlRnJhbWVVUkwoKSB7XG4gICAgcmV0dXJuIHRoaXMuY3VzdG9tUGFnZXMucGFyc2VGcmFtZVVSTDtcbiAgfVxuXG4gIGdldCB2ZXJpZnlFbWFpbFVSTCgpIHtcbiAgICByZXR1cm4gYCR7dGhpcy5wdWJsaWNTZXJ2ZXJVUkx9L2FwcHMvJHt0aGlzLmFwcGxpY2F0aW9uSWR9L3ZlcmlmeV9lbWFpbGA7XG4gIH1cbn1cblxuZXhwb3J0IGRlZmF1bHQgQ29uZmlnO1xubW9kdWxlLmV4cG9ydHMgPSBDb25maWc7XG4iXX0=