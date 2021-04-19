"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = exports.UsersRouter = void 0;

var _node = _interopRequireDefault(require("parse/node"));

var _Config = _interopRequireDefault(require("../Config"));

var _AccountLockout = _interopRequireDefault(require("../AccountLockout"));

var _ClassesRouter = _interopRequireDefault(require("./ClassesRouter"));

var _rest = _interopRequireDefault(require("../rest"));

var _Auth = _interopRequireDefault(require("../Auth"));

var _password = _interopRequireDefault(require("../password"));

var _triggers = require("../triggers");

var _middlewares = require("../middlewares");

var _RestWrite = _interopRequireDefault(require("../RestWrite"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

class UsersRouter extends _ClassesRouter.default {
  className() {
    return '_User';
  }
  /**
   * Removes all "_" prefixed properties from an object, except "__type"
   * @param {Object} obj An object.
   */


  static removeHiddenProperties(obj) {
    for (var key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        // Regexp comes from Parse.Object.prototype.validate
        if (key !== '__type' && !/^[A-Za-z][0-9A-Za-z_]*$/.test(key)) {
          delete obj[key];
        }
      }
    }
  }
  /**
   * Validates a password request in login and verifyPassword
   * @param {Object} req The request
   * @returns {Object} User object
   * @private
   */


  _authenticateUserFromRequest(req) {
    return new Promise((resolve, reject) => {
      // Use query parameters instead if provided in url
      let payload = req.body;

      if (!payload.username && req.query && req.query.username || !payload.email && req.query && req.query.email) {
        payload = req.query;
      }

      const {
        username,
        email,
        password
      } = payload; // TODO: use the right error codes / descriptions.

      if (!username && !email) {
        throw new _node.default.Error(_node.default.Error.USERNAME_MISSING, 'username/email is required.');
      }

      if (!password) {
        throw new _node.default.Error(_node.default.Error.PASSWORD_MISSING, 'password is required.');
      }

      if (typeof password !== 'string' || email && typeof email !== 'string' || username && typeof username !== 'string') {
        throw new _node.default.Error(_node.default.Error.OBJECT_NOT_FOUND, 'Invalid username/password.');
      }

      let user;
      let isValidPassword = false;
      let query;

      if (email && username) {
        query = {
          email,
          username
        };
      } else if (email) {
        query = {
          email
        };
      } else {
        query = {
          $or: [{
            username
          }, {
            email: username
          }]
        };
      }

      return req.config.database.find('_User', query).then(results => {
        if (!results.length) {
          throw new _node.default.Error(_node.default.Error.OBJECT_NOT_FOUND, 'Invalid username/password.');
        }

        if (results.length > 1) {
          // corner case where user1 has username == user2 email
          req.config.loggerController.warn("There is a user which email is the same as another user's username, logging in based on username");
          user = results.filter(user => user.username === username)[0];
        } else {
          user = results[0];
        }

        return _password.default.compare(password, user.password);
      }).then(correct => {
        isValidPassword = correct;
        const accountLockoutPolicy = new _AccountLockout.default(user, req.config);
        return accountLockoutPolicy.handleLoginAttempt(isValidPassword);
      }).then(() => {
        if (!isValidPassword) {
          throw new _node.default.Error(_node.default.Error.OBJECT_NOT_FOUND, 'Invalid username/password.');
        } // Ensure the user isn't locked out
        // A locked out user won't be able to login
        // To lock a user out, just set the ACL to `masterKey` only  ({}).
        // Empty ACL is OK


        if (!req.auth.isMaster && user.ACL && Object.keys(user.ACL).length == 0) {
          throw new _node.default.Error(_node.default.Error.OBJECT_NOT_FOUND, 'Invalid username/password.');
        }

        if (req.config.verifyUserEmails && req.config.preventLoginWithUnverifiedEmail && !user.emailVerified) {
          throw new _node.default.Error(_node.default.Error.EMAIL_NOT_FOUND, 'User email is not verified.');
        }

        delete user.password; // Sometimes the authData still has null on that keys
        // https://github.com/parse-community/parse-server/issues/935

        if (user.authData) {
          Object.keys(user.authData).forEach(provider => {
            if (user.authData[provider] === null) {
              delete user.authData[provider];
            }
          });

          if (Object.keys(user.authData).length == 0) {
            delete user.authData;
          }
        }

        return resolve(user);
      }).catch(error => {
        return reject(error);
      });
    });
  }

  handleMe(req) {
    if (!req.info || !req.info.sessionToken) {
      throw new _node.default.Error(_node.default.Error.INVALID_SESSION_TOKEN, 'Invalid session token');
    }

    const sessionToken = req.info.sessionToken;
    return _rest.default.find(req.config, _Auth.default.master(req.config), '_Session', {
      sessionToken
    }, {
      include: 'user'
    }, req.info.clientSDK, req.info.context).then(response => {
      if (!response.results || response.results.length == 0 || !response.results[0].user) {
        throw new _node.default.Error(_node.default.Error.INVALID_SESSION_TOKEN, 'Invalid session token');
      } else {
        const user = response.results[0].user; // Send token back on the login, because SDKs expect that.

        user.sessionToken = sessionToken; // Remove hidden properties.

        UsersRouter.removeHiddenProperties(user);
        return {
          response: user
        };
      }
    });
  }

  async handleLogIn(req) {
    const user = await this._authenticateUserFromRequest(req); // handle password expiry policy

    if (req.config.passwordPolicy && req.config.passwordPolicy.maxPasswordAge) {
      let changedAt = user._password_changed_at;

      if (!changedAt) {
        // password was created before expiry policy was enabled.
        // simply update _User object so that it will start enforcing from now
        changedAt = new Date();
        req.config.database.update('_User', {
          username: user.username
        }, {
          _password_changed_at: _node.default._encode(changedAt)
        });
      } else {
        // check whether the password has expired
        if (changedAt.__type == 'Date') {
          changedAt = new Date(changedAt.iso);
        } // Calculate the expiry time.


        const expiresAt = new Date(changedAt.getTime() + 86400000 * req.config.passwordPolicy.maxPasswordAge);
        if (expiresAt < new Date()) // fail of current time is past password expiry time
          throw new _node.default.Error(_node.default.Error.OBJECT_NOT_FOUND, 'Your password has expired. Please reset your password.');
      }
    } // Remove hidden properties.


    UsersRouter.removeHiddenProperties(user);
    req.config.filesController.expandFilesInObject(req.config, user); // Before login trigger; throws if failure

    await (0, _triggers.maybeRunTrigger)(_triggers.Types.beforeLogin, req.auth, _node.default.User.fromJSON(Object.assign({
      className: '_User'
    }, user)), null, req.config);

    const {
      sessionData,
      createSession
    } = _RestWrite.default.createSession(req.config, {
      userId: user.objectId,
      createdWith: {
        action: 'login',
        authProvider: 'password'
      },
      installationId: req.info.installationId
    });

    user.sessionToken = sessionData.sessionToken;
    await createSession();

    const afterLoginUser = _node.default.User.fromJSON(Object.assign({
      className: '_User'
    }, user));

    (0, _triggers.maybeRunTrigger)(_triggers.Types.afterLogin, _objectSpread(_objectSpread({}, req.auth), {}, {
      user: afterLoginUser
    }), afterLoginUser, null, req.config);
    return {
      response: user
    };
  }

  handleVerifyPassword(req) {
    return this._authenticateUserFromRequest(req).then(user => {
      // Remove hidden properties.
      UsersRouter.removeHiddenProperties(user);
      return {
        response: user
      };
    }).catch(error => {
      throw error;
    });
  }

  handleLogOut(req) {
    const success = {
      response: {}
    };

    if (req.info && req.info.sessionToken) {
      return _rest.default.find(req.config, _Auth.default.master(req.config), '_Session', {
        sessionToken: req.info.sessionToken
      }, undefined, req.info.clientSDK, req.info.context).then(records => {
        if (records.results && records.results.length) {
          return _rest.default.del(req.config, _Auth.default.master(req.config), '_Session', records.results[0].objectId, req.info.context).then(() => {
            this._runAfterLogoutTrigger(req, records.results[0]);

            return Promise.resolve(success);
          });
        }

        return Promise.resolve(success);
      });
    }

    return Promise.resolve(success);
  }

  _runAfterLogoutTrigger(req, session) {
    // After logout trigger
    (0, _triggers.maybeRunTrigger)(_triggers.Types.afterLogout, req.auth, _node.default.Session.fromJSON(Object.assign({
      className: '_Session'
    }, session)), null, req.config);
  }

  _throwOnBadEmailConfig(req) {
    try {
      _Config.default.validateEmailConfiguration({
        emailAdapter: req.config.userController.adapter,
        appName: req.config.appName,
        publicServerURL: req.config.publicServerURL,
        emailVerifyTokenValidityDuration: req.config.emailVerifyTokenValidityDuration,
        emailVerifyTokenReuseIfValid: req.config.emailVerifyTokenReuseIfValid
      });
    } catch (e) {
      if (typeof e === 'string') {
        // Maybe we need a Bad Configuration error, but the SDKs won't understand it. For now, Internal Server Error.
        throw new _node.default.Error(_node.default.Error.INTERNAL_SERVER_ERROR, 'An appName, publicServerURL, and emailAdapter are required for password reset and email verification functionality.');
      } else {
        throw e;
      }
    }
  }

  handleResetRequest(req) {
    this._throwOnBadEmailConfig(req);

    const {
      email
    } = req.body;

    if (!email) {
      throw new _node.default.Error(_node.default.Error.EMAIL_MISSING, 'you must provide an email');
    }

    if (typeof email !== 'string') {
      throw new _node.default.Error(_node.default.Error.INVALID_EMAIL_ADDRESS, 'you must provide a valid email string');
    }

    const userController = req.config.userController;
    return userController.sendPasswordResetEmail(email).then(() => {
      return Promise.resolve({
        response: {}
      });
    }, err => {
      if (err.code === _node.default.Error.OBJECT_NOT_FOUND) {
        // Return success so that this endpoint can't
        // be used to enumerate valid emails
        return Promise.resolve({
          response: {}
        });
      } else {
        throw err;
      }
    });
  }

  handleVerificationEmailRequest(req) {
    this._throwOnBadEmailConfig(req);

    const {
      email
    } = req.body;

    if (!email) {
      throw new _node.default.Error(_node.default.Error.EMAIL_MISSING, 'you must provide an email');
    }

    if (typeof email !== 'string') {
      throw new _node.default.Error(_node.default.Error.INVALID_EMAIL_ADDRESS, 'you must provide a valid email string');
    }

    return req.config.database.find('_User', {
      email: email
    }).then(results => {
      if (!results.length || results.length < 1) {
        throw new _node.default.Error(_node.default.Error.EMAIL_NOT_FOUND, `No user found with email ${email}`);
      }

      const user = results[0]; // remove password field, messes with saving on postgres

      delete user.password;

      if (user.emailVerified) {
        throw new _node.default.Error(_node.default.Error.OTHER_CAUSE, `Email ${email} is already verified.`);
      }

      const userController = req.config.userController;
      return userController.regenerateEmailVerifyToken(user).then(() => {
        userController.sendVerificationEmail(user);
        return {
          response: {}
        };
      });
    });
  }

  mountRoutes() {
    this.route('GET', '/users', req => {
      return this.handleFind(req);
    });
    this.route('POST', '/users', _middlewares.promiseEnsureIdempotency, req => {
      return this.handleCreate(req);
    });
    this.route('GET', '/users/me', req => {
      return this.handleMe(req);
    });
    this.route('GET', '/users/:objectId', req => {
      return this.handleGet(req);
    });
    this.route('PUT', '/users/:objectId', _middlewares.promiseEnsureIdempotency, req => {
      return this.handleUpdate(req);
    });
    this.route('DELETE', '/users/:objectId', req => {
      return this.handleDelete(req);
    });
    this.route('GET', '/login', req => {
      return this.handleLogIn(req);
    });
    this.route('POST', '/login', req => {
      return this.handleLogIn(req);
    });
    this.route('POST', '/logout', req => {
      return this.handleLogOut(req);
    });
    this.route('POST', '/requestPasswordReset', req => {
      return this.handleResetRequest(req);
    });
    this.route('POST', '/verificationEmailRequest', req => {
      return this.handleVerificationEmailRequest(req);
    });
    this.route('GET', '/verifyPassword', req => {
      return this.handleVerifyPassword(req);
    });
  }

}

exports.UsersRouter = UsersRouter;
var _default = UsersRouter;
exports.default = _default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9Sb3V0ZXJzL1VzZXJzUm91dGVyLmpzIl0sIm5hbWVzIjpbIlVzZXJzUm91dGVyIiwiQ2xhc3Nlc1JvdXRlciIsImNsYXNzTmFtZSIsInJlbW92ZUhpZGRlblByb3BlcnRpZXMiLCJvYmoiLCJrZXkiLCJPYmplY3QiLCJwcm90b3R5cGUiLCJoYXNPd25Qcm9wZXJ0eSIsImNhbGwiLCJ0ZXN0IiwiX2F1dGhlbnRpY2F0ZVVzZXJGcm9tUmVxdWVzdCIsInJlcSIsIlByb21pc2UiLCJyZXNvbHZlIiwicmVqZWN0IiwicGF5bG9hZCIsImJvZHkiLCJ1c2VybmFtZSIsInF1ZXJ5IiwiZW1haWwiLCJwYXNzd29yZCIsIlBhcnNlIiwiRXJyb3IiLCJVU0VSTkFNRV9NSVNTSU5HIiwiUEFTU1dPUkRfTUlTU0lORyIsIk9CSkVDVF9OT1RfRk9VTkQiLCJ1c2VyIiwiaXNWYWxpZFBhc3N3b3JkIiwiJG9yIiwiY29uZmlnIiwiZGF0YWJhc2UiLCJmaW5kIiwidGhlbiIsInJlc3VsdHMiLCJsZW5ndGgiLCJsb2dnZXJDb250cm9sbGVyIiwid2FybiIsImZpbHRlciIsInBhc3N3b3JkQ3J5cHRvIiwiY29tcGFyZSIsImNvcnJlY3QiLCJhY2NvdW50TG9ja291dFBvbGljeSIsIkFjY291bnRMb2Nrb3V0IiwiaGFuZGxlTG9naW5BdHRlbXB0IiwiYXV0aCIsImlzTWFzdGVyIiwiQUNMIiwia2V5cyIsInZlcmlmeVVzZXJFbWFpbHMiLCJwcmV2ZW50TG9naW5XaXRoVW52ZXJpZmllZEVtYWlsIiwiZW1haWxWZXJpZmllZCIsIkVNQUlMX05PVF9GT1VORCIsImF1dGhEYXRhIiwiZm9yRWFjaCIsInByb3ZpZGVyIiwiY2F0Y2giLCJlcnJvciIsImhhbmRsZU1lIiwiaW5mbyIsInNlc3Npb25Ub2tlbiIsIklOVkFMSURfU0VTU0lPTl9UT0tFTiIsInJlc3QiLCJBdXRoIiwibWFzdGVyIiwiaW5jbHVkZSIsImNsaWVudFNESyIsImNvbnRleHQiLCJyZXNwb25zZSIsImhhbmRsZUxvZ0luIiwicGFzc3dvcmRQb2xpY3kiLCJtYXhQYXNzd29yZEFnZSIsImNoYW5nZWRBdCIsIl9wYXNzd29yZF9jaGFuZ2VkX2F0IiwiRGF0ZSIsInVwZGF0ZSIsIl9lbmNvZGUiLCJfX3R5cGUiLCJpc28iLCJleHBpcmVzQXQiLCJnZXRUaW1lIiwiZmlsZXNDb250cm9sbGVyIiwiZXhwYW5kRmlsZXNJbk9iamVjdCIsIlRyaWdnZXJUeXBlcyIsImJlZm9yZUxvZ2luIiwiVXNlciIsImZyb21KU09OIiwiYXNzaWduIiwic2Vzc2lvbkRhdGEiLCJjcmVhdGVTZXNzaW9uIiwiUmVzdFdyaXRlIiwidXNlcklkIiwib2JqZWN0SWQiLCJjcmVhdGVkV2l0aCIsImFjdGlvbiIsImF1dGhQcm92aWRlciIsImluc3RhbGxhdGlvbklkIiwiYWZ0ZXJMb2dpblVzZXIiLCJhZnRlckxvZ2luIiwiaGFuZGxlVmVyaWZ5UGFzc3dvcmQiLCJoYW5kbGVMb2dPdXQiLCJzdWNjZXNzIiwidW5kZWZpbmVkIiwicmVjb3JkcyIsImRlbCIsIl9ydW5BZnRlckxvZ291dFRyaWdnZXIiLCJzZXNzaW9uIiwiYWZ0ZXJMb2dvdXQiLCJTZXNzaW9uIiwiX3Rocm93T25CYWRFbWFpbENvbmZpZyIsIkNvbmZpZyIsInZhbGlkYXRlRW1haWxDb25maWd1cmF0aW9uIiwiZW1haWxBZGFwdGVyIiwidXNlckNvbnRyb2xsZXIiLCJhZGFwdGVyIiwiYXBwTmFtZSIsInB1YmxpY1NlcnZlclVSTCIsImVtYWlsVmVyaWZ5VG9rZW5WYWxpZGl0eUR1cmF0aW9uIiwiZW1haWxWZXJpZnlUb2tlblJldXNlSWZWYWxpZCIsImUiLCJJTlRFUk5BTF9TRVJWRVJfRVJST1IiLCJoYW5kbGVSZXNldFJlcXVlc3QiLCJFTUFJTF9NSVNTSU5HIiwiSU5WQUxJRF9FTUFJTF9BRERSRVNTIiwic2VuZFBhc3N3b3JkUmVzZXRFbWFpbCIsImVyciIsImNvZGUiLCJoYW5kbGVWZXJpZmljYXRpb25FbWFpbFJlcXVlc3QiLCJPVEhFUl9DQVVTRSIsInJlZ2VuZXJhdGVFbWFpbFZlcmlmeVRva2VuIiwic2VuZFZlcmlmaWNhdGlvbkVtYWlsIiwibW91bnRSb3V0ZXMiLCJyb3V0ZSIsImhhbmRsZUZpbmQiLCJwcm9taXNlRW5zdXJlSWRlbXBvdGVuY3kiLCJoYW5kbGVDcmVhdGUiLCJoYW5kbGVHZXQiLCJoYW5kbGVVcGRhdGUiLCJoYW5kbGVEZWxldGUiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFFQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7Ozs7Ozs7OztBQUVPLE1BQU1BLFdBQU4sU0FBMEJDLHNCQUExQixDQUF3QztBQUM3Q0MsRUFBQUEsU0FBUyxHQUFHO0FBQ1YsV0FBTyxPQUFQO0FBQ0Q7QUFFRDtBQUNGO0FBQ0E7QUFDQTs7O0FBQytCLFNBQXRCQyxzQkFBc0IsQ0FBQ0MsR0FBRCxFQUFNO0FBQ2pDLFNBQUssSUFBSUMsR0FBVCxJQUFnQkQsR0FBaEIsRUFBcUI7QUFDbkIsVUFBSUUsTUFBTSxDQUFDQyxTQUFQLENBQWlCQyxjQUFqQixDQUFnQ0MsSUFBaEMsQ0FBcUNMLEdBQXJDLEVBQTBDQyxHQUExQyxDQUFKLEVBQW9EO0FBQ2xEO0FBQ0EsWUFBSUEsR0FBRyxLQUFLLFFBQVIsSUFBb0IsQ0FBQywwQkFBMEJLLElBQTFCLENBQStCTCxHQUEvQixDQUF6QixFQUE4RDtBQUM1RCxpQkFBT0QsR0FBRyxDQUFDQyxHQUFELENBQVY7QUFDRDtBQUNGO0FBQ0Y7QUFDRjtBQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FBQ0VNLEVBQUFBLDRCQUE0QixDQUFDQyxHQUFELEVBQU07QUFDaEMsV0FBTyxJQUFJQyxPQUFKLENBQVksQ0FBQ0MsT0FBRCxFQUFVQyxNQUFWLEtBQXFCO0FBQ3RDO0FBQ0EsVUFBSUMsT0FBTyxHQUFHSixHQUFHLENBQUNLLElBQWxCOztBQUNBLFVBQ0csQ0FBQ0QsT0FBTyxDQUFDRSxRQUFULElBQXFCTixHQUFHLENBQUNPLEtBQXpCLElBQWtDUCxHQUFHLENB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LElBQUk7QUFDbEMsYUFBTyxLQUFLeUQsV0FBTCxDQUFpQnpELEdBQWpCLENBQVA7QUFDRCxLQUZEO0FBR0EsU0FBS3dILEtBQUwsQ0FBVyxNQUFYLEVBQW1CLFNBQW5CLEVBQThCeEgsR0FBRyxJQUFJO0FBQ25DLGFBQU8sS0FBS3dGLFlBQUwsQ0FBa0J4RixHQUFsQixDQUFQO0FBQ0QsS0FGRDtBQUdBLFNBQUt3SCxLQUFMLENBQVcsTUFBWCxFQUFtQix1QkFBbkIsRUFBNEN4SCxHQUFHLElBQUk7QUFDakQsYUFBTyxLQUFLNkcsa0JBQUwsQ0FBd0I3RyxHQUF4QixDQUFQO0FBQ0QsS0FGRDtBQUdBLFNBQUt3SCxLQUFMLENBQVcsTUFBWCxFQUFtQiwyQkFBbkIsRUFBZ0R4SCxHQUFHLElBQUk7QUFDckQsYUFBTyxLQUFLbUgsOEJBQUwsQ0FBb0NuSCxHQUFwQyxDQUFQO0FBQ0QsS0FGRDtBQUdBLFNBQUt3SCxLQUFMLENBQVcsS0FBWCxFQUFrQixpQkFBbEIsRUFBcUN4SCxHQUFHLElBQUk7QUFDMUMsYUFBTyxLQUFLdUYsb0JBQUwsQ0FBMEJ2RixHQUExQixDQUFQO0FBQ0QsS0FGRDtBQUdEOztBQW5hNEM7OztlQXNhaENaLFciLCJzb3VyY2VzQ29udGVudCI6WyIvLyBUaGVzZSBtZXRob2RzIGhhbmRsZSB0aGUgVXNlci1yZWxhdGVkIHJvdXRlcy5cblxuaW1wb3J0IFBhcnNlIGZyb20gJ3BhcnNlL25vZGUnO1xuaW1wb3J0IENvbmZpZyBmcm9tICcuLi9Db25maWcnO1xuaW1wb3J0IEFjY291bnRMb2Nrb3V0IGZyb20gJy4uL0FjY291bnRMb2Nrb3V0JztcbmltcG9ydCBDbGFzc2VzUm91dGVyIGZyb20gJy4vQ2xhc3Nlc1JvdXRlcic7XG5pbXBvcnQgcmVzdCBmcm9tICcuLi9yZXN0JztcbmltcG9ydCBBdXRoIGZyb20gJy4uL0F1dGgnO1xuaW1wb3J0IHBhc3N3b3JkQ3J5cHRvIGZyb20gJy4uL3Bhc3N3b3JkJztcbmltcG9ydCB7IG1heWJlUnVuVHJpZ2dlciwgVHlwZXMgYXMgVHJpZ2dlclR5cGVzIH0gZnJvbSAnLi4vdHJpZ2dlcnMnO1xuaW1wb3J0IHsgcHJvbWlzZUVuc3VyZUlkZW1wb3RlbmN5IH0gZnJvbSAnLi4vbWlkZGxld2FyZXMnO1xuaW1wb3J0IFJlc3RXcml0ZSBmcm9tICcuLi9SZXN0V3JpdGUnO1xuXG5leHBvcnQgY2xhc3MgVXNlcnNSb3V0ZXIgZXh0ZW5kcyBDbGFzc2VzUm91dGVyIHtcbiAgY2xhc3NOYW1lKCkge1xuICAgIHJldHVybiAnX1VzZXInO1xuICB9XG5cbiAgLyoqXG4gICAqIFJlbW92ZXMgYWxsIFwiX1wiIHByZWZpeGVkIHByb3BlcnRpZXMgZnJvbSBhbiBvYmplY3QsIGV4Y2VwdCBcIl9fdHlwZVwiXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBvYmogQW4gb2JqZWN0LlxuICAgKi9cbiAgc3RhdGljIHJlbW92ZUhpZGRlblByb3BlcnRpZXMob2JqKSB7XG4gICAgZm9yICh2YXIga2V5IGluIG9iaikge1xuICAgICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmosIGtleSkpIHtcbiAgICAgICAgLy8gUmVnZXhwIGNvbWVzIGZyb20gUGFyc2UuT2JqZWN0LnByb3RvdHlwZS52YWxpZGF0ZVxuICAgICAgICBpZiAoa2V5ICE9PSAnX190eXBlJyAmJiAhL15bQS1aYS16XVswLTlBLVphLXpfXSokLy50ZXN0KGtleSkpIHtcbiAgICAgICAgICBkZWxldGUgb2JqW2tleV07XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVmFsaWRhdGVzIGEgcGFzc3dvcmQgcmVxdWVzdCBpbiBsb2dpbiBhbmQgdmVyaWZ5UGFzc3dvcmRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcSBUaGUgcmVxdWVzdFxuICAgKiBAcmV0dXJucyB7T2JqZWN0fSBVc2VyIG9iamVjdFxuICAgKiBAcHJpdmF0ZVxuICAgKi9cbiAgX2F1dGhlbnRpY2F0ZVVzZXJGcm9tUmVxdWVzdChyZXEpIHtcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgICAgLy8gVXNlIHF1ZXJ5IHBhcmFtZXRlcnMgaW5zdGVhZCBpZiBwcm92aWRlZCBpbiB1cmxcbiAgICAgIGxldCBwYXlsb2FkID0gcmVxLmJvZHk7XG4gICAgICBpZiAoXG4gICAgICAgICghcGF5bG9hZC51c2VybmFtZSAmJiByZXEucXVlcnkgJiYgcmVxLnF1ZXJ5LnVzZXJuYW1lKSB8fFxuICAgICAgICAoIXBheWxvYWQuZW1haWwgJiYgcmVxLnF1ZXJ5ICYmIHJlcS5xdWVyeS5lbWFpbClcbiAgICAgICkge1xuICAgICAgICBwYXlsb2FkID0gcmVxLnF1ZXJ5O1xuICAgICAgfVxuICAgICAgY29uc3QgeyB1c2VybmFtZSwgZW1haWwsIHBhc3N3b3JkIH0gPSBwYXlsb2FkO1xuXG4gICAgICAvLyBUT0RPOiB1c2UgdGhlIHJpZ2h0IGVycm9yIGNvZGVzIC8gZGVzY3JpcHRpb25zLlxuICAgICAgaWYgKCF1c2VybmFtZSAmJiAhZW1haWwpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLlVTRVJOQU1FX01JU1NJTkcsICd1c2VybmFtZS9lbWFpbCBpcyByZXF1aXJlZC4nKTtcbiAgICAgIH1cbiAgICAgIGlmICghcGFzc3dvcmQpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLlBBU1NXT1JEX01JU1NJTkcsICdwYXNzd29yZCBpcyByZXF1aXJlZC4nKTtcbiAgICAgIH1cbiAgICAgIGlmIChcbiAgICAgICAgdHlwZW9mIHBhc3N3b3JkICE9PSAnc3RyaW5nJyB8fFxuICAgICAgICAoZW1haWwgJiYgdHlwZW9mIGVtYWlsICE9PSAnc3RyaW5nJykgfHxcbiAgICAgICAgKHVzZXJuYW1lICYmIHR5cGVvZiB1c2VybmFtZSAhPT0gJ3N0cmluZycpXG4gICAgICApIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLk9CSkVDVF9OT1RfRk9VTkQsICdJbnZhbGlkIHVzZXJuYW1lL3Bhc3N3b3JkLicpO1xuICAgICAgfVxuXG4gICAgICBsZXQgdXNlcjtcbiAgICAgIGxldCBpc1ZhbGlkUGFzc3dvcmQgPSBmYWxzZTtcbiAgICAgIGxldCBxdWVyeTtcbiAgICAgIGlmIChlbWFpbCAmJiB1c2VybmFtZSkge1xuICAgICAgICBxdWVyeSA9IHsgZW1haWwsIHVzZXJuYW1lIH07XG4gICAgICB9IGVsc2UgaWYgKGVtYWlsKSB7XG4gICAgICAgIHF1ZXJ5ID0geyBlbWFpbCB9O1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcXVlcnkgPSB7ICRvcjogW3sgdXNlcm5hbWUgfSwgeyBlbWFpbDogdXNlcm5hbWUgfV0gfTtcbiAgICAgIH1cbiAgICAgIHJldHVybiByZXEuY29uZmlnLmRhdGFiYXNlXG4gICAgICAgIC5maW5kKCdfVXNlcicsIHF1ZXJ5KVxuICAgICAgICAudGhlbihyZXN1bHRzID0+IHtcbiAgICAgICAgICBpZiAoIXJlc3VsdHMubGVuZ3RoKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuT0JKRUNUX05PVF9GT1VORCwgJ0ludmFsaWQgdXNlcm5hbWUvcGFzc3dvcmQuJyk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgaWYgKHJlc3VsdHMubGVuZ3RoID4gMSkge1xuICAgICAgICAgICAgLy8gY29ybmVyIGNhc2Ugd2hlcmUgdXNlcjEgaGFzIHVzZXJuYW1lID09IHVzZXIyIGVtYWlsXG4gICAgICAgICAgICByZXEuY29uZmlnLmxvZ2dlckNvbnRyb2xsZXIud2FybihcbiAgICAgICAgICAgICAgXCJUaGVyZSBpcyBhIHVzZXIgd2hpY2ggZW1haWwgaXMgdGhlIHNhbWUgYXMgYW5vdGhlciB1c2VyJ3MgdXNlcm5hbWUsIGxvZ2dpbmcgaW4gYmFzZWQgb24gdXNlcm5hbWVcIlxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHVzZXIgPSByZXN1bHRzLmZpbHRlcih1c2VyID0+IHVzZXIudXNlcm5hbWUgPT09IHVzZXJuYW1lKVswXTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdXNlciA9IHJlc3VsdHNbMF07XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIHBhc3N3b3JkQ3J5cHRvLmNvbXBhcmUocGFzc3dvcmQsIHVzZXIucGFzc3dvcmQpO1xuICAgICAgICB9KVxuICAgICAgICAudGhlbihjb3JyZWN0ID0+IHtcbiAgICAgICAgICBpc1ZhbGlkUGFzc3dvcmQgPSBjb3JyZWN0O1xuICAgICAgICAgIGNvbnN0IGFjY291bnRMb2Nrb3V0UG9saWN5ID0gbmV3IEFjY291bnRMb2Nrb3V0KHVzZXIsIHJlcS5jb25maWcpO1xuICAgICAgICAgIHJldHVybiBhY2NvdW50TG9ja291dFBvbGljeS5oYW5kbGVMb2dpbkF0dGVtcHQoaXNWYWxpZFBhc3N3b3JkKTtcbiAgICAgICAgfSlcbiAgICAgICAgLnRoZW4oKCkgPT4ge1xuICAgICAgICAgIGlmICghaXNWYWxpZFBhc3N3b3JkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuT0JKRUNUX05PVF9GT1VORCwgJ0ludmFsaWQgdXNlcm5hbWUvcGFzc3dvcmQuJyk7XG4gICAgICAgICAgfVxuICAgICAgICAgIC8vIEVuc3VyZSB0aGUgdXNlciBpc24ndCBsb2NrZWQgb3V0XG4gICAgICAgICAgLy8gQSBsb2NrZWQgb3V0IHVzZXIgd29uJ3QgYmUgYWJsZSB0byBsb2dpblxuICAgICAgICAgIC8vIFRvIGxvY2sgYSB1c2VyIG91dCwganVzdCBzZXQgdGhlIEFDTCB0byBgbWFzdGVyS2V5YCBvbmx5ICAoe30pLlxuICAgICAgICAgIC8vIEVtcHR5IEFDTCBpcyBPS1xuICAgICAgICAgIGlmICghcmVxLmF1dGguaXNNYXN0ZXIgJiYgdXNlci5BQ0wgJiYgT2JqZWN0LmtleXModXNlci5BQ0wpLmxlbmd0aCA9PSAwKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuT0JKRUNUX05PVF9GT1VORCwgJ0ludmFsaWQgdXNlcm5hbWUvcGFzc3dvcmQuJyk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGlmIChcbiAgICAgICAgICAgIHJlcS5jb25maWcudmVyaWZ5VXNlckVtYWlscyAmJlxuICAgICAgICAgICAgcmVxLmNvbmZpZy5wcmV2ZW50TG9naW5XaXRoVW52ZXJpZmllZEVtYWlsICYmXG4gICAgICAgICAgICAhdXNlci5lbWFpbFZlcmlmaWVkXG4gICAgICAgICAgKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuRU1BSUxfTk9UX0ZPVU5ELCAnVXNlciBlbWFpbCBpcyBub3QgdmVyaWZpZWQuJyk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgZGVsZXRlIHVzZXIucGFzc3dvcmQ7XG5cbiAgICAgICAgICAvLyBTb21ldGltZXMgdGhlIGF1dGhEYXRhIHN0aWxsIGhhcyBudWxsIG9uIHRoYXQga2V5c1xuICAgICAgICAgIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9wYXJzZS1jb21tdW5pdHkvcGFyc2Utc2VydmVyL2lzc3Vlcy85MzVcbiAgICAgICAgICBpZiAodXNlci5hdXRoRGF0YSkge1xuICAgICAgICAgICAgT2JqZWN0LmtleXModXNlci5hdXRoRGF0YSkuZm9yRWFjaChwcm92aWRlciA9PiB7XG4gICAgICAgICAgICAgIGlmICh1c2VyLmF1dGhEYXRhW3Byb3ZpZGVyXSA9PT0gbnVsbCkge1xuICAgICAgICAgICAgICAgIGRlbGV0ZSB1c2VyLmF1dGhEYXRhW3Byb3ZpZGVyXTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBpZiAoT2JqZWN0LmtleXModXNlci5hdXRoRGF0YSkubGVuZ3RoID09IDApIHtcbiAgICAgICAgICAgICAgZGVsZXRlIHVzZXIuYXV0aERhdGE7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgcmV0dXJuIHJlc29sdmUodXNlcik7XG4gICAgICAgIH0pXG4gICAgICAgIC5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgICAgcmV0dXJuIHJlamVjdChlcnJvcik7XG4gICAgICAgIH0pO1xuICAgIH0pO1xuICB9XG5cbiAgaGFuZGxlTWUocmVxKSB7XG4gICAgaWYgKCFyZXEuaW5mbyB8fCAhcmVxLmluZm8uc2Vzc2lvblRva2VuKSB7XG4gICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9TRVNTSU9OX1RPS0VOLCAnSW52YWxpZCBzZXNzaW9uIHRva2VuJyk7XG4gICAgfVxuICAgIGNvbnN0IHNlc3Npb25Ub2tlbiA9IHJlcS5pbmZvLnNlc3Npb25Ub2tlbjtcbiAgICByZXR1cm4gcmVzdFxuICAgICAgLmZpbmQoXG4gICAgICAgIHJlcS5jb25maWcsXG4gICAgICAgIEF1dGgubWFzdGVyKHJlcS5jb25maWcpLFxuICAgICAgICAnX1Nlc3Npb24nLFxuICAgICAgICB7IHNlc3Npb25Ub2tlbiB9LFxuICAgICAgICB7IGluY2x1ZGU6ICd1c2VyJyB9LFxuICAgICAgICByZXEuaW5mby5jbGllbnRTREssXG4gICAgICAgIHJlcS5pbmZvLmNvbnRleHRcbiAgICAgIClcbiAgICAgIC50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgICAgaWYgKCFyZXNwb25zZS5yZXN1bHRzIHx8IHJlc3BvbnNlLnJlc3VsdHMubGVuZ3RoID09IDAgfHwgIXJlc3BvbnNlLnJlc3VsdHNbMF0udXNlcikge1xuICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX1NFU1NJT05fVE9LRU4sICdJbnZhbGlkIHNlc3Npb24gdG9rZW4nKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBjb25zdCB1c2VyID0gcmVzcG9uc2UucmVzdWx0c1swXS51c2VyO1xuICAgICAgICAgIC8vIFNlbmQgdG9rZW4gYmFjayBvbiB0aGUgbG9naW4sIGJlY2F1c2UgU0RLcyBleHBlY3QgdGhhdC5cbiAgICAgICAgICB1c2VyLnNlc3Npb25Ub2tlbiA9IHNlc3Npb25Ub2tlbjtcblxuICAgICAgICAgIC8vIFJlbW92ZSBoaWRkZW4gcHJvcGVydGllcy5cbiAgICAgICAgICBVc2Vyc1JvdXRlci5yZW1vdmVIaWRkZW5Qcm9wZXJ0aWVzKHVzZXIpO1xuXG4gICAgICAgICAgcmV0dXJuIHsgcmVzcG9uc2U6IHVzZXIgfTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gIH1cblxuICBhc3luYyBoYW5kbGVMb2dJbihyZXEpIHtcbiAgICBjb25zdCB1c2VyID0gYXdhaXQgdGhpcy5fYXV0aGVudGljYXRlVXNlckZyb21SZXF1ZXN0KHJlcSk7XG5cbiAgICAvLyBoYW5kbGUgcGFzc3dvcmQgZXhwaXJ5IHBvbGljeVxuICAgIGlmIChyZXEuY29uZmlnLnBhc3N3b3JkUG9saWN5ICYmIHJlcS5jb25maWcucGFzc3dvcmRQb2xpY3kubWF4UGFzc3dvcmRBZ2UpIHtcbiAgICAgIGxldCBjaGFuZ2VkQXQgPSB1c2VyLl9wYXNzd29yZF9jaGFuZ2VkX2F0O1xuXG4gICAgICBpZiAoIWNoYW5nZWRBdCkge1xuICAgICAgICAvLyBwYXNzd29yZCB3YXMgY3JlYXRlZCBiZWZvcmUgZXhwaXJ5IHBvbGljeSB3YXMgZW5hYmxlZC5cbiAgICAgICAgLy8gc2ltcGx5IHVwZGF0ZSBfVXNlciBvYmplY3Qgc28gdGhhdCBpdCB3aWxsIHN0YXJ0IGVuZm9yY2luZyBmcm9tIG5vd1xuICAgICAgICBjaGFuZ2VkQXQgPSBuZXcgRGF0ZSgpO1xuICAgICAgICByZXEuY29uZmlnLmRhdGFiYXNlLnVwZGF0ZShcbiAgICAgICAgICAnX1VzZXInLFxuICAgICAgICAgIHsgdXNlcm5hbWU6IHVzZXIudXNlcm5hbWUgfSxcbiAgICAgICAgICB7IF9wYXNzd29yZF9jaGFuZ2VkX2F0OiBQYXJzZS5fZW5jb2RlKGNoYW5nZWRBdCkgfVxuICAgICAgICApO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gY2hlY2sgd2hldGhlciB0aGUgcGFzc3dvcmQgaGFzIGV4cGlyZWRcbiAgICAgICAgaWYgKGNoYW5nZWRBdC5fX3R5cGUgPT0gJ0RhdGUnKSB7XG4gICAgICAgICAgY2hhbmdlZEF0ID0gbmV3IERhdGUoY2hhbmdlZEF0Lmlzbyk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gQ2FsY3VsYXRlIHRoZSBleHBpcnkgdGltZS5cbiAgICAgICAgY29uc3QgZXhwaXJlc0F0ID0gbmV3IERhdGUoXG4gICAgICAgICAgY2hhbmdlZEF0LmdldFRpbWUoKSArIDg2NDAwMDAwICogcmVxLmNvbmZpZy5wYXNzd29yZFBvbGljeS5tYXhQYXNzd29yZEFnZVxuICAgICAgICApO1xuICAgICAgICBpZiAoZXhwaXJlc0F0IDwgbmV3IERhdGUoKSlcbiAgICAgICAgICAvLyBmYWlsIG9mIGN1cnJlbnQgdGltZSBpcyBwYXN0IHBhc3N3b3JkIGV4cGlyeSB0aW1lXG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuT0JKRUNUX05PVF9GT1VORCxcbiAgICAgICAgICAgICdZb3VyIHBhc3N3b3JkIGhhcyBleHBpcmVkLiBQbGVhc2UgcmVzZXQgeW91ciBwYXNzd29yZC4nXG4gICAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBSZW1vdmUgaGlkZGVuIHByb3BlcnRpZXMuXG4gICAgVXNlcnNSb3V0ZXIucmVtb3ZlSGlkZGVuUHJvcGVydGllcyh1c2VyKTtcblxuICAgIHJlcS5jb25maWcuZmlsZXNDb250cm9sbGVyLmV4cGFuZEZpbGVzSW5PYmplY3QocmVxLmNvbmZpZywgdXNlcik7XG5cbiAgICAvLyBCZWZvcmUgbG9naW4gdHJpZ2dlcjsgdGhyb3dzIGlmIGZhaWx1cmVcbiAgICBhd2FpdCBtYXliZVJ1blRyaWdnZXIoXG4gICAgICBUcmlnZ2VyVHlwZXMuYmVmb3JlTG9naW4sXG4gICAgICByZXEuYXV0aCxcbiAgICAgIFBhcnNlLlVzZXIuZnJvbUpTT04oT2JqZWN0LmFzc2lnbih7IGNsYXNzTmFtZTogJ19Vc2VyJyB9LCB1c2VyKSksXG4gICAgICBudWxsLFxuICAgICAgcmVxLmNvbmZpZ1xuICAgICk7XG5cbiAgICBjb25zdCB7IHNlc3Npb25EYXRhLCBjcmVhdGVTZXNzaW9uIH0gPSBSZXN0V3JpdGUuY3JlYXRlU2Vzc2lvbihyZXEuY29uZmlnLCB7XG4gICAgICB1c2VySWQ6IHVzZXIub2JqZWN0SWQsXG4gICAgICBjcmVhdGVkV2l0aDoge1xuICAgICAgICBhY3Rpb246ICdsb2dpbicsXG4gICAgICAgIGF1dGhQcm92aWRlcjogJ3Bhc3N3b3JkJyxcbiAgICAgIH0sXG4gICAgICBpbnN0YWxsYXRpb25JZDogcmVxLmluZm8uaW5zdGFsbGF0aW9uSWQsXG4gICAgfSk7XG5cbiAgICB1c2VyLnNlc3Npb25Ub2tlbiA9IHNlc3Npb25EYXRhLnNlc3Npb25Ub2tlbjtcblxuICAgIGF3YWl0IGNyZWF0ZVNlc3Npb24oKTtcblxuICAgIGNvbnN0IGFmdGVyTG9naW5Vc2VyID0gUGFyc2UuVXNlci5mcm9tSlNPTihPYmplY3QuYXNzaWduKHsgY2xhc3NOYW1lOiAnX1VzZXInIH0sIHVzZXIpKTtcbiAgICBtYXliZVJ1blRyaWdnZXIoXG4gICAgICBUcmlnZ2VyVHlwZXMuYWZ0ZXJMb2dpbixcbiAgICAgIHsgLi4ucmVxLmF1dGgsIHVzZXI6IGFmdGVyTG9naW5Vc2VyIH0sXG4gICAgICBhZnRlckxvZ2luVXNlcixcbiAgICAgIG51bGwsXG4gICAgICByZXEuY29uZmlnXG4gICAgKTtcblxuICAgIHJldHVybiB7IHJlc3BvbnNlOiB1c2VyIH07XG4gIH1cblxuICBoYW5kbGVWZXJpZnlQYXNzd29yZChyZXEpIHtcbiAgICByZXR1cm4gdGhpcy5fYXV0aGVudGljYXRlVXNlckZyb21SZXF1ZXN0KHJlcSlcbiAgICAgIC50aGVuKHVzZXIgPT4ge1xuICAgICAgICAvLyBSZW1vdmUgaGlkZGVuIHByb3BlcnRpZXMuXG4gICAgICAgIFVzZXJzUm91dGVyLnJlbW92ZUhpZGRlblByb3BlcnRpZXModXNlcik7XG5cbiAgICAgICAgcmV0dXJuIHsgcmVzcG9uc2U6IHVzZXIgfTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH0pO1xuICB9XG5cbiAgaGFuZGxlTG9nT3V0KHJlcSkge1xuICAgIGNvbnN0IHN1Y2Nlc3MgPSB7IHJlc3BvbnNlOiB7fSB9O1xuICAgIGlmIChyZXEuaW5mbyAmJiByZXEuaW5mby5zZXNzaW9uVG9rZW4pIHtcbiAgICAgIHJldHVybiByZXN0XG4gICAgICAgIC5maW5kKFxuICAgICAgICAgIHJlcS5jb25maWcsXG4gICAgICAgICAgQXV0aC5tYXN0ZXIocmVxLmNvbmZpZyksXG4gICAgICAgICAgJ19TZXNzaW9uJyxcbiAgICAgICAgICB7IHNlc3Npb25Ub2tlbjogcmVxLmluZm8uc2Vzc2lvblRva2VuIH0sXG4gICAgICAgICAgdW5kZWZpbmVkLFxuICAgICAgICAgIHJlcS5pbmZvLmNsaWVudFNESyxcbiAgICAgICAgICByZXEuaW5mby5jb250ZXh0XG4gICAgICAgIClcbiAgICAgICAgLnRoZW4ocmVjb3JkcyA9PiB7XG4gICAgICAgICAgaWYgKHJlY29yZHMucmVzdWx0cyAmJiByZWNvcmRzLnJlc3VsdHMubGVuZ3RoKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzdFxuICAgICAgICAgICAgICAuZGVsKFxuICAgICAgICAgICAgICAgIHJlcS5jb25maWcsXG4gICAgICAgICAgICAgICAgQXV0aC5tYXN0ZXIocmVxLmNvbmZpZyksXG4gICAgICAgICAgICAgICAgJ19TZXNzaW9uJyxcbiAgICAgICAgICAgICAgICByZWNvcmRzLnJlc3VsdHNbMF0ub2JqZWN0SWQsXG4gICAgICAgICAgICAgICAgcmVxLmluZm8uY29udGV4dFxuICAgICAgICAgICAgICApXG4gICAgICAgICAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgICAgICAgICB0aGlzLl9ydW5BZnRlckxvZ291dFRyaWdnZXIocmVxLCByZWNvcmRzLnJlc3VsdHNbMF0pO1xuICAgICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoc3VjY2Vzcyk7XG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHN1Y2Nlc3MpO1xuICAgICAgICB9KTtcbiAgICB9XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShzdWNjZXNzKTtcbiAgfVxuXG4gIF9ydW5BZnRlckxvZ291dFRyaWdnZXIocmVxLCBzZXNzaW9uKSB7XG4gICAgLy8gQWZ0ZXIgbG9nb3V0IHRyaWdnZXJcbiAgICBtYXliZVJ1blRyaWdnZXIoXG4gICAgICBUcmlnZ2VyVHlwZXMuYWZ0ZXJMb2dvdXQsXG4gICAgICByZXEuYXV0aCxcbiAgICAgIFBhcnNlLlNlc3Npb24uZnJvbUpTT04oT2JqZWN0LmFzc2lnbih7IGNsYXNzTmFtZTogJ19TZXNzaW9uJyB9LCBzZXNzaW9uKSksXG4gICAgICBudWxsLFxuICAgICAgcmVxLmNvbmZpZ1xuICAgICk7XG4gIH1cblxuICBfdGhyb3dPbkJhZEVtYWlsQ29uZmlnKHJlcSkge1xuICAgIHRyeSB7XG4gICAgICBDb25maWcudmFsaWRhdGVFbWFpbENvbmZpZ3VyYXRpb24oe1xuICAgICAgICBlbWFpbEFkYXB0ZXI6IHJlcS5jb25maWcudXNlckNvbnRyb2xsZXIuYWRhcHRlcixcbiAgICAgICAgYXBwTmFtZTogcmVxLmNvbmZpZy5hcHBOYW1lLFxuICAgICAgICBwdWJsaWNTZXJ2ZXJVUkw6IHJlcS5jb25maWcucHVibGljU2VydmVyVVJMLFxuICAgICAgICBlbWFpbFZlcmlmeVRva2VuVmFsaWRpdHlEdXJhdGlvbjogcmVxLmNvbmZpZy5lbWFpbFZlcmlmeVRva2VuVmFsaWRpdHlEdXJhdGlvbixcbiAgICAgICAgZW1haWxWZXJpZnlUb2tlblJldXNlSWZWYWxpZDogcmVxLmNvbmZpZy5lbWFpbFZlcmlmeVRva2VuUmV1c2VJZlZhbGlkLFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgaWYgKHR5cGVvZiBlID09PSAnc3RyaW5nJykge1xuICAgICAgICAvLyBNYXliZSB3ZSBuZWVkIGEgQmFkIENvbmZpZ3VyYXRpb24gZXJyb3IsIGJ1dCB0aGUgU0RLcyB3b24ndCB1bmRlcnN0YW5kIGl0LiBGb3Igbm93LCBJbnRlcm5hbCBTZXJ2ZXIgRXJyb3IuXG4gICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICBQYXJzZS5FcnJvci5JTlRFUk5BTF9TRVJWRVJfRVJST1IsXG4gICAgICAgICAgJ0FuIGFwcE5hbWUsIHB1YmxpY1NlcnZlclVSTCwgYW5kIGVtYWlsQWRhcHRlciBhcmUgcmVxdWlyZWQgZm9yIHBhc3N3b3JkIHJlc2V0IGFuZCBlbWFpbCB2ZXJpZmljYXRpb24gZnVuY3Rpb25hbGl0eS4nXG4gICAgICAgICk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aHJvdyBlO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIGhhbmRsZVJlc2V0UmVxdWVzdChyZXEpIHtcbiAgICB0aGlzLl90aHJvd09uQmFkRW1haWxDb25maWcocmVxKTtcblxuICAgIGNvbnN0IHsgZW1haWwgfSA9IHJlcS5ib2R5O1xuICAgIGlmICghZW1haWwpIHtcbiAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5FTUFJTF9NSVNTSU5HLCAneW91IG11c3QgcHJvdmlkZSBhbiBlbWFpbCcpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIGVtYWlsICE9PSAnc3RyaW5nJykge1xuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0VNQUlMX0FERFJFU1MsXG4gICAgICAgICd5b3UgbXVzdCBwcm92aWRlIGEgdmFsaWQgZW1haWwgc3RyaW5nJ1xuICAgICAgKTtcbiAgICB9XG4gICAgY29uc3QgdXNlckNvbnRyb2xsZXIgPSByZXEuY29uZmlnLnVzZXJDb250cm9sbGVyO1xuICAgIHJldHVybiB1c2VyQ29udHJvbGxlci5zZW5kUGFzc3dvcmRSZXNldEVtYWlsKGVtYWlsKS50aGVuKFxuICAgICAgKCkgPT4ge1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHtcbiAgICAgICAgICByZXNwb25zZToge30sXG4gICAgICAgIH0pO1xuICAgICAgfSxcbiAgICAgIGVyciA9PiB7XG4gICAgICAgIGlmIChlcnIuY29kZSA9PT0gUGFyc2UuRXJyb3IuT0JKRUNUX05PVF9GT1VORCkge1xuICAgICAgICAgIC8vIFJldHVybiBzdWNjZXNzIHNvIHRoYXQgdGhpcyBlbmRwb2ludCBjYW4ndFxuICAgICAgICAgIC8vIGJlIHVzZWQgdG8gZW51bWVyYXRlIHZhbGlkIGVtYWlsc1xuICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoe1xuICAgICAgICAgICAgcmVzcG9uc2U6IHt9LFxuICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHRocm93IGVycjtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICk7XG4gIH1cblxuICBoYW5kbGVWZXJpZmljYXRpb25FbWFpbFJlcXVlc3QocmVxKSB7XG4gICAgdGhpcy5fdGhyb3dPbkJhZEVtYWlsQ29uZmlnKHJlcSk7XG5cbiAgICBjb25zdCB7IGVtYWlsIH0gPSByZXEuYm9keTtcbiAgICBpZiAoIWVtYWlsKSB7XG4gICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuRU1BSUxfTUlTU0lORywgJ3lvdSBtdXN0IHByb3ZpZGUgYW4gZW1haWwnKTtcbiAgICB9XG4gICAgaWYgKHR5cGVvZiBlbWFpbCAhPT0gJ3N0cmluZycpIHtcbiAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9FTUFJTF9BRERSRVNTLFxuICAgICAgICAneW91IG11c3QgcHJvdmlkZSBhIHZhbGlkIGVtYWlsIHN0cmluZydcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHJlcS5jb25maWcuZGF0YWJhc2UuZmluZCgnX1VzZXInLCB7IGVtYWlsOiBlbWFpbCB9KS50aGVuKHJlc3VsdHMgPT4ge1xuICAgICAgaWYgKCFyZXN1bHRzLmxlbmd0aCB8fCByZXN1bHRzLmxlbmd0aCA8IDEpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLkVNQUlMX05PVF9GT1VORCwgYE5vIHVzZXIgZm91bmQgd2l0aCBlbWFpbCAke2VtYWlsfWApO1xuICAgICAgfVxuICAgICAgY29uc3QgdXNlciA9IHJlc3VsdHNbMF07XG5cbiAgICAgIC8vIHJlbW92ZSBwYXNzd29yZCBmaWVsZCwgbWVzc2VzIHdpdGggc2F2aW5nIG9uIHBvc3RncmVzXG4gICAgICBkZWxldGUgdXNlci5wYXNzd29yZDtcblxuICAgICAgaWYgKHVzZXIuZW1haWxWZXJpZmllZCkge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuT1RIRVJfQ0FVU0UsIGBFbWFpbCAke2VtYWlsfSBpcyBhbHJlYWR5IHZlcmlmaWVkLmApO1xuICAgICAgfVxuXG4gICAgICBjb25zdCB1c2VyQ29udHJvbGxlciA9IHJlcS5jb25maWcudXNlckNvbnRyb2xsZXI7XG4gICAgICByZXR1cm4gdXNlckNvbnRyb2xsZXIucmVnZW5lcmF0ZUVtYWlsVmVyaWZ5VG9rZW4odXNlcikudGhlbigoKSA9PiB7XG4gICAgICAgIHVzZXJDb250cm9sbGVyLnNlbmRWZXJpZmljYXRpb25FbWFpbCh1c2VyKTtcbiAgICAgICAgcmV0dXJuIHsgcmVzcG9uc2U6IHt9IH07XG4gICAgICB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIG1vdW50Um91dGVzKCkge1xuICAgIHRoaXMucm91dGUoJ0dFVCcsICcvdXNlcnMnLCByZXEgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMuaGFuZGxlRmluZChyZXEpO1xuICAgIH0pO1xuICAgIHRoaXMucm91dGUoJ1BPU1QnLCAnL3VzZXJzJywgcHJvbWlzZUVuc3VyZUlkZW1wb3RlbmN5LCByZXEgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMuaGFuZGxlQ3JlYXRlKHJlcSk7XG4gICAgfSk7XG4gICAgdGhpcy5yb3V0ZSgnR0VUJywgJy91c2Vycy9tZScsIHJlcSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy5oYW5kbGVNZShyZXEpO1xuICAgIH0pO1xuICAgIHRoaXMucm91dGUoJ0dFVCcsICcvdXNlcnMvOm9iamVjdElkJywgcmVxID0+IHtcbiAgICAgIHJldHVybiB0aGlzLmhhbmRsZUdldChyZXEpO1xuICAgIH0pO1xuICAgIHRoaXMucm91dGUoJ1BVVCcsICcvdXNlcnMvOm9iamVjdElkJywgcHJvbWlzZUVuc3VyZUlkZW1wb3RlbmN5LCByZXEgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMuaGFuZGxlVXBkYXRlKHJlcSk7XG4gICAgfSk7XG4gICAgdGhpcy5yb3V0ZSgnREVMRVRFJywgJy91c2Vycy86b2JqZWN0SWQnLCByZXEgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMuaGFuZGxlRGVsZXRlKHJlcSk7XG4gICAgfSk7XG4gICAgdGhpcy5yb3V0ZSgnR0VUJywgJy9sb2dpbicsIHJlcSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy5oYW5kbGVMb2dJbihyZXEpO1xuICAgIH0pO1xuICAgIHRoaXMucm91dGUoJ1BPU1QnLCAnL2xvZ2luJywgcmVxID0+IHtcbiAgICAgIHJldHVybiB0aGlzLmhhbmRsZUxvZ0luKHJlcSk7XG4gICAgfSk7XG4gICAgdGhpcy5yb3V0ZSgnUE9TVCcsICcvbG9nb3V0JywgcmVxID0+IHtcbiAgICAgIHJldHVybiB0aGlzLmhhbmRsZUxvZ091dChyZXEpO1xuICAgIH0pO1xuICAgIHRoaXMucm91dGUoJ1BPU1QnLCAnL3JlcXVlc3RQYXNzd29yZFJlc2V0JywgcmVxID0+IHtcbiAgICAgIHJldHVybiB0aGlzLmhhbmRsZVJlc2V0UmVxdWVzdChyZXEpO1xuICAgIH0pO1xuICAgIHRoaXMucm91dGUoJ1BPU1QnLCAnL3ZlcmlmaWNhdGlvbkVtYWlsUmVxdWVzdCcsIHJlcSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy5oYW5kbGVWZXJpZmljYXRpb25FbWFpbFJlcXVlc3QocmVxKTtcbiAgICB9KTtcbiAgICB0aGlzLnJvdXRlKCdHRVQnLCAnL3ZlcmlmeVBhc3N3b3JkJywgcmVxID0+IHtcbiAgICAgIHJldHVybiB0aGlzLmhhbmRsZVZlcmlmeVBhc3N3b3JkKHJlcSk7XG4gICAgfSk7XG4gIH1cbn1cblxuZXhwb3J0IGRlZmF1bHQgVXNlcnNSb3V0ZXI7XG4iXX0=