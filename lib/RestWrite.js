"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _RestQuery = _interopRequireDefault(require("./RestQuery"));

var _lodash = _interopRequireDefault(require("lodash"));

var _logger = _interopRequireDefault(require("./logger"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// A RestWrite encapsulates everything we need to run an operation
// that writes to the database.
// This could be either a "create" or an "update".
var SchemaController = require('./Controllers/SchemaController');

var deepcopy = require('deepcopy');

const Auth = require('./Auth');

var cryptoUtils = require('./cryptoUtils');

var passwordCrypto = require('./password');

var Parse = require('parse/node');

var triggers = require('./triggers');

var ClientSDK = require('./ClientSDK');

// query and data are both provided in REST API format. So data
// types are encoded by plain old objects.
// If query is null, this is a "create" and the data in data should be
// created.
// Otherwise this is an "update" - the object matching the query
// should get updated with data.
// RestWrite will handle objectId, createdAt, and updatedAt for
// everything. It also knows to use triggers and special modifications
// for the _User class.
function RestWrite(config, auth, className, query, data, originalData, clientSDK, context, action) {
  if (auth.isReadOnly) {
    throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, 'Cannot perform a write operation when using readOnlyMasterKey');
  }

  this.config = config;
  this.auth = auth;
  this.className = className;
  this.clientSDK = clientSDK;
  this.storage = {};
  this.runOptions = {};
  this.context = context || {};

  if (action) {
    this.runOptions.action = action;
  }

  if (!query) {
    if (this.config.allowCustomObjectId) {
      if (Object.prototype.hasOwnProperty.call(data, 'objectId') && !data.objectId) {
        throw new Parse.Error(Parse.Error.MISSING_OBJECT_ID, 'objectId must not be empty, null or undefined');
      }
    } else {
      if (data.objectId) {
        throw new Parse.Error(Parse.Error.INVALID_KEY_NAME, 'objectId is an invalid field name.');
      }

      if (data.id) {
        throw new Parse.Error(Parse.Error.INVALID_KEY_NAME, 'id is an invalid field name.');
      }
    }
  } // When the operation is complete, this.response may have several
  // fields.
  // response: the actual data to be returned
  // status: the http status code. if not present, treated like a 200
  // location: the location header. if not present, no location header


  this.response = null; // Processing this operation may mutate our data, so we operate on a
  // copy

  this.query = deepcopy(query);
  this.data = deepcopy(data); // We never change originalData, so we do not need a deep copy

  this.originalData = originalData; // The timestamp we'll use for this whole operation

  this.updatedAt = Parse._encode(new Date()).iso; // Shared SchemaController to be reused to reduce the number of loadSchema() calls per request
  // Once set the schemaData should be immutable

  this.validSchemaController = null;
} // A convenient method to perform all the steps of processing the
// write, in order.
// Returns a promise for a {response, status, location} object.
// status and location are optional.


RestWrite.prototype.execute = function () {
  return Promise.resolve().then(() => {
    return this.getUserAndRoleACL();
  }).then(() => {
    return this.validateClientClassCreation();
  }).then(() => {
    return this.handleInstallation();
  }).then(() => {
    return this.handleSession();
  }).then(() => {
    return this.validateAuthData();
  }).then(() => {
    return this.runBeforeSaveTrigger();
  }).then(() => {
    return this.deleteEmailResetTokenIfNeeded();
  }).then(() => {
    return this.validateSchema();
  }).then(schemaController => {
    this.validSchemaController = schemaController;
    return this.setRequiredFieldsIfNeeded();
  }).then(() => {
    return this.transformUser();
  }).then(() => {
    return this.expandFilesForExistingObjects();
  }).then(() => {
    return this.destroyDuplicatedSessions();
  }).then(() => {
    return this.runDatabaseOperation();
  }).then(() => {
    return this.createSessionTokenIfNeeded();
  }).then(() => {
    return this.handleFollowup();
  }).then(() => {
    return this.runAfterSaveTrigger();
  }).then(() => {
    return this.cleanUserAuthData();
  }).then(() => {
    return this.response;
  });
}; // Uses the Auth object to get the list of roles, adds the user id


RestWrite.prototype.getUserAndRoleACL = function () {
  if (this.auth.isMaster) {
    return Promise.resolve();
  }

  this.runOptions.acl = ['*'];

  if (this.auth.user) {
    return this.auth.getUserRoles().then(roles => {
      this.runOptions.acl = this.runOptions.acl.concat(roles, [this.auth.user.id]);
      return;
    });
  } else {
    return Promise.resolve();
  }
}; // Validates this operation against the allowClientClassCreation config.


RestWrite.prototype.validateClientClassCreation = function () {
  if (this.config.allowClientClassCreation === false && !this.auth.isMaster && SchemaController.systemClasses.indexOf(this.className) === -1) {
    return this.config.database.loadSchema().then(schemaController => schemaController.hasClass(this.className)).then(hasClass => {
      if (hasClass !== true) {
        throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, 'This user is not allowed to access ' + 'non-existent class: ' + this.className);
      }
    });
  } else {
    return Promise.resolve();
  }
}; // Validates this operation against the schema.


RestWrite.prototype.validateSchema = function () {
  return this.config.database.validateObject(this.className, this.data, this.query, this.runOptions);
}; // Runs any beforeSave triggers against this operation.
// Any change leads to our data being mutated.


RestWrite.prototype.runBeforeSaveTrigger = function () {
  if (this.response) {
    return;
  } // Avoid doing any setup for triggers if there is no 'beforeSave' trigger for this class.


  if (!triggers.triggerExists(this.className, triggers.Types.beforeSave, this.config.applicationId)) {
    return Promise.resolve();
  } // Cloud code gets a bit of extra data for its objects


  var extraData = {
    className: this.className
  };

  if (this.query && this.query.objectId) {
    extraData.objectId = this.query.objectId;
  }

  let originalObject = null;
  const updatedObject = this.buildUpdatedObject(extraData);

  if (this.query && this.query.objectId) {
    // This is an update for existing object.
    originalObject = triggers.inflate(extraData, this.originalData);
  }

  return Promise.resolve().then(() => {
    // Before calling the trigger, validate the permissions for the save operation
    let databasePromise = null;

    if (this.query) {
      // Validate for updating
      databasePromise = this.config.database.update(this.className, this.query, this.data, this.runOptions, true, true);
    } else {
      // Validate for creating
      databasePromise = this.config.database.create(this.className, this.data, this.runOptions, true);
    } // In the case that there is no permission for the operation, it throws an error


    return databasePromise.then(result => {
      if (!result || result.length <= 0) {
        throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Object not found.');
      }
    });
  }).then(() => {
    return triggers.maybeRunTrigger(triggers.Types.beforeSave, this.auth, updatedObject, originalObject, this.config, this.context);
  }).then(response => {
    if (response && response.object) {
      this.storage.fieldsChangedByTrigger = _lodash.default.reduce(response.object, (result, value, key) => {
        if (!_lodash.default.isEqual(this.data[key], value)) {
          result.push(key);
        }

        return result;
      }, []);
      this.data = response.object; // We should delete the objectId for an update write

      if (this.query && this.query.objectId) {
        delete this.data.objectId;
      }
    }
  });
};

RestWrite.prototype.runBeforeLoginTrigger = async function (userData) {
  // Avoid doing any setup for triggers if there is no 'beforeLogin' trigger
  if (!triggers.triggerExists(this.className, triggers.Types.beforeLogin, this.config.applicationId)) {
    return;
  } // Cloud code gets a bit of extra data for its objects


  const extraData = {
    className: this.className
  }; // Expand file objects

  this.config.filesController.expandFilesInObject(this.config, userData);
  const user = triggers.inflate(extraData, userData); // no need to return a response

  await triggers.maybeRunTrigger(triggers.Types.beforeLogin, this.auth, user, null, this.config, this.context);
};

RestWrite.prototype.setRequiredFieldsIfNeeded = function () {
  if (this.data) {
    return this.validSchemaController.getAllClasses().then(allClasses => {
      const schema = allClasses.find(oneClass => oneClass.className === this.className);

      const setRequiredFieldIfNeeded = (fieldName, setDefault) => {
        if (this.data[fieldName] === undefined || this.data[fieldName] === null || this.data[fieldName] === '' || typeof this.data[fieldName] === 'object' && this.data[fieldName].__op === 'Delete') {
          if (setDefault && schema.fields[fieldName] && schema.fields[fieldName].defaultValue !== null && schema.fields[fieldName].defaultValue !== undefined && (this.data[fieldName] === undefined || typeof this.data[fieldName] === 'object' && this.data[fieldName].__op === 'Delete')) {
            this.data[fieldName] = schema.fields[fieldName].defaultValue;
            this.storage.fieldsChangedByTrigger = this.storage.fieldsChangedByTrigger || [];

            if (this.storage.fieldsChangedByTrigger.indexOf(fieldName) < 0) {
              this.storage.fieldsChangedByTrigger.push(fieldName);
            }
          } else if (schema.fields[fieldName] && schema.fields[fieldName].required === true) {
            throw new Parse.Error(Parse.Error.VALIDATION_ERROR, `${fieldName} is required`);
          }
        }
      }; // Add default fields


      this.data.updatedAt = this.updatedAt;

      if (!this.query) {
        this.data.createdAt = this.updatedAt; // Only assign new objectId if we are creating new object

        if (!this.data.objectId) {
          this.data.objectId = cryptoUtils.newObjectId(this.config.objectIdSize);
        }

        if (schema) {
          Object.keys(schema.fields).forEach(fieldName => {
            setRequiredFieldIfNeeded(fieldName, true);
          });
        }
      } else if (schema) {
        Object.keys(this.data).forEach(fieldName => {
          setRequiredFieldIfNeeded(fieldName, false);
        });
      }
    });
  }

  return Promise.resolve();
}; // Transforms auth data for a user object.
// Does nothing if this isn't a user object.
// Returns a promise for when we're done if it can't finish this tick.


RestWrite.prototype.validateAuthData = function () {
  if (this.className !== '_User') {
    return;
  }

  if (!this.query && !this.data.authData) {
    if (typeof this.data.username !== 'string' || _lodash.default.isEmpty(this.data.username)) {
      throw new Parse.Error(Parse.Error.USERNAME_MISSING, 'bad or missing username');
    }

    if (typeof this.data.password !== 'string' || _lodash.default.isEmpty(this.data.password)) {
      throw new Parse.Error(Parse.Error.PASSWORD_MISSING, 'password is required');
    }
  }

  if (this.data.authData && !Object.keys(this.data.authData).length || !Object.prototype.hasOwnProperty.call(this.data, 'authData')) {
    // Handle saving authData to {} or if authData doesn't exist
    return;
  } else if (Object.prototype.hasOwnProperty.call(this.data, 'authData') && !this.data.authData) {
    // Handle saving authData to null
    throw new Parse.Error(Parse.Error.UNSUPPORTED_SERVICE, 'This authentication method is unsupported.');
  }

  var authData = this.data.authData;
  var providers = Object.keys(authData);

  if (providers.length > 0) {
    const canHandleAuthData = providers.reduce((canHandle, provider) => {
      var providerAuthData = authData[provider];
      var hasToken = providerAuthData && providerAuthData.id;
      return canHandle && (hasToken || providerAuthData == null);
    }, true);

    if (canHandleAuthData) {
      return this.handleAuthData(authData);
    }
  }

  throw new Parse.Error(Parse.Error.UNSUPPORTED_SERVICE, 'This authentication method is unsupported.');
};

RestWrite.prototype.handleAuthDataValidation = function (authData) {
  const validations = Object.keys(authData).map(provider => {
    if (authData[provider] === null) {
      return Promise.resolve();
    }

    const validateAuthData = this.config.authDataManager.getValidatorForProvider(provider);

    if (!validateAuthData) {
      throw new Parse.Error(Parse.Error.UNSUPPORTED_SERVICE, 'This authentication method is unsupported.');
    }

    return validateAuthData(authData[provider]);
  });
  return Promise.all(validations);
};

RestWrite.prototype.findUsersWithAuthData = function (authData) {
  const providers = Object.keys(authData);
  const query = providers.reduce((memo, provider) => {
    if (!authData[provider]) {
      return memo;
    }

    const queryKey = `authData.${provider}.id`;
    const query = {};
    query[queryKey] = authData[provider].id;
    memo.push(query);
    return memo;
  }, []).filter(q => {
    return typeof q !== 'undefined';
  });
  let findPromise = Promise.resolve([]);

  if (query.length > 0) {
    findPromise = this.config.database.find(this.className, {
      $or: query
    }, {});
  }

  return findPromise;
};

RestWrite.prototype.filteredObjectsByACL = function (objects) {
  if (this.auth.isMaster) {
    return objects;
  }

  return objects.filter(object => {
    if (!object.ACL) {
      return true; // legacy users that have no ACL field on them
    } // Regular users that have been locked out.


    return object.ACL && Object.keys(object.ACL).length > 0;
  });
};

RestWrite.prototype.handleAuthData = function (authData) {
  let results;
  return this.findUsersWithAuthData(authData).then(async r => {
    results = this.filteredObjectsByACL(r);

    if (results.length == 1) {
      this.storage['authProvider'] = Object.keys(authData).join(',');
      const userResult = results[0];
      const mutatedAuthData = {};
      Object.keys(authData).forEach(provider => {
        const providerData = authData[provider];
        const userAuthData = userResult.authData[provider];

        if (!_lodash.default.isEqual(providerData, userAuthData)) {
          mutatedAuthData[provider] = providerData;
        }
      });
      const hasMutatedAuthData = Object.keys(mutatedAuthData).length !== 0;
      let userId;

      if (this.query && this.query.objectId) {
        userId = this.query.objectId;
      } else if (this.auth && this.auth.user && this.auth.user.id) {
        userId = this.auth.user.id;
      }

      if (!userId || userId === userResult.objectId) {
        // no user making the call
        // OR the user making the call is the right one
        // Login with auth data
        delete results[0].password; // need to set the objectId first otherwise location has trailing undefined

        this.data.objectId = userResult.objectId;

        if (!this.query || !this.query.objectId) {
          // this a login call, no userId passed
          this.response = {
            response: userResult,
            location: this.location()
          }; // Run beforeLogin hook before storing any updates
          // to authData on the db; changes to userResult
          // will be ignored.

          await this.runBeforeLoginTrigger(deepcopy(userResult));
        } // If we didn't change the auth data, just keep going


        if (!hasMutatedAuthData) {
          return;
        } // We have authData that is updated on login
        // that can happen when token are refreshed,
        // We should update the token and let the user in
        // We should only check the mutated keys


        return this.handleAuthDataValidation(mutatedAuthData).then(async () => {
          // IF we have a response, we'll skip the database operation / beforeSave / afterSave etc...
          // we need to set it up there.
          // We are supposed to have a response only on LOGIN with authData, so we skip those
          // If we're not logging in, but just updating the current user, we can safely skip that part
          if (this.response) {
            // Assign the new authData in the response
            Object.keys(mutatedAuthData).forEach(provider => {
              this.response.response.authData[provider] = mutatedAuthData[provider];
            }); // Run the DB update directly, as 'master'
            // Just update the authData part
            // Then we're good for the user, early exit of sorts

            return this.config.database.update(this.className, {
              objectId: this.data.objectId
            }, {
              authData: mutatedAuthData
            }, {});
          }
        });
      } else if (userId) {
        // Trying to update auth data but users
        // are different
        if (userResult.objectId !== userId) {
          throw new Parse.Error(Parse.Error.ACCOUNT_ALREADY_LINKED, 'this auth is already used');
        } // No auth data was mutated, just keep going


        if (!hasMutatedAuthData) {
          return;
        }
      }
    }

    return this.handleAuthDataValidation(authData).then(() => {
      if (results.length > 1) {
        // More than 1 user with the passed id's
        throw new Parse.Error(Parse.Error.ACCOUNT_ALREADY_LINKED, 'this auth is already used');
      }
    });
  });
}; // The non-third-party parts of User transformation


RestWrite.prototype.transformUser = function () {
  var promise = Promise.resolve();

  if (this.className !== '_User') {
    return promise;
  }

  if (!this.auth.isMaster && 'emailVerified' in this.data) {
    const error = `Clients aren't allowed to manually update email verification.`;
    throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, error);
  } // Do not cleanup session if objectId is not set


  if (this.query && this.objectId()) {
    // If we're updating a _User object, we need to clear out the cache for that user. Find all their
    // session tokens, and remove them from the cache.
    promise = new _RestQuery.default(this.config, Auth.master(this.config), '_Session', {
      user: {
        __type: 'Pointer',
        className: '_User',
        objectId: this.objectId()
      }
    }).execute().then(results => {
      results.results.forEach(session => this.config.cacheController.user.del(session.sessionToken));
    });
  }

  return promise.then(() => {
    // Transform the password
    if (this.data.password === undefined) {
      // ignore only if undefined. should proceed if empty ('')
      return Promise.resolve();
    }

    if (this.query) {
      this.storage['clearSessions'] = true; // Generate a new session only if the user requested

      if (!this.auth.isMaster) {
        this.storage['generateNewSession'] = true;
      }
    }

    return this._validatePasswordPolicy().then(() => {
      return passwordCrypto.hash(this.data.password).then(hashedPassword => {
        this.data._hashed_password = hashedPassword;
        delete this.data.password;
      });
    });
  }).then(() => {
    return this._validateUserName();
  }).then(() => {
    return this._validateEmail();
  });
};

RestWrite.prototype._validateUserName = function () {
  // Check for username uniqueness
  if (!this.data.username) {
    if (!this.query) {
      this.data.username = cryptoUtils.randomString(25);
      this.responseShouldHaveUsername = true;
    }

    return Promise.resolve();
  }
  /*
    Usernames should be unique when compared case insensitively
     Users should be able to make case sensitive usernames and
    login using the case they entered.  I.e. 'Snoopy' should preclude
    'snoopy' as a valid username.
  */


  return this.config.database.find(this.className, {
    username: this.data.username,
    objectId: {
      $ne: this.objectId()
    }
  }, {
    limit: 1,
    caseInsensitive: true
  }, {}, this.validSchemaController).then(results => {
    if (results.length > 0) {
      throw new Parse.Error(Parse.Error.USERNAME_TAKEN, 'Account already exists for this username.');
    }

    return;
  });
};
/*
  As with usernames, Parse should not allow case insensitive collisions of email.
  unlike with usernames (which can have case insensitive collisions in the case of
  auth adapters), emails should never have a case insensitive collision.

  This behavior can be enforced through a properly configured index see:
  https://docs.mongodb.com/manual/core/index-case-insensitive/#create-a-case-insensitive-index
  which could be implemented instead of this code based validation.

  Given that this lookup should be a relatively low use case and that the case sensitive
  unique index will be used by the db for the query, this is an adequate solution.
*/


RestWrite.prototype._validateEmail = function () {
  if (!this.data.email || this.data.email.__op === 'Delete') {
    return Promise.resolve();
  } // Validate basic email address format


  if (!this.data.email.match(/^.+@.+$/)) {
    return Promise.reject(new Parse.Error(Parse.Error.INVALID_EMAIL_ADDRESS, 'Email address format is invalid.'));
  } // Case insensitive match, see note above function.


  return this.config.database.find(this.className, {
    email: this.data.email,
    objectId: {
      $ne: this.objectId()
    }
  }, {
    limit: 1,
    caseInsensitive: true
  }, {}, this.validSchemaController).then(results => {
    if (results.length > 0) {
      throw new Parse.Error(Parse.Error.EMAIL_TAKEN, 'Account already exists for this email address.');
    }

    if (!this.data.authData || !Object.keys(this.data.authData).length || Object.keys(this.data.authData).length === 1 && Object.keys(this.data.authData)[0] === 'anonymous') {
      // We updated the email, send a new validation
      this.storage['sendVerificationEmail'] = true;
      this.config.userController.setEmailVerifyToken(this.data);
    }
  });
};

RestWrite.prototype._validatePasswordPolicy = function () {
  if (!this.config.passwordPolicy) return Promise.resolve();
  return this._validatePasswordRequirements().then(() => {
    return this._validatePasswordHistory();
  });
};

RestWrite.prototype._validatePasswordRequirements = function () {
  // check if the password conforms to the defined password policy if configured
  // If we specified a custom error in our configuration use it.
  // Example: "Passwords must include a Capital Letter, Lowercase Letter, and a number."
  //
  // This is especially useful on the generic "password reset" page,
  // as it allows the programmer to communicate specific requirements instead of:
  // a. making the user guess whats wrong
  // b. making a custom password reset page that shows the requirements
  const policyError = this.config.passwordPolicy.validationError ? this.config.passwordPolicy.validationError : 'Password does not meet the Password Policy requirements.';
  const containsUsernameError = 'Password cannot contain your username.'; // check whether the password meets the password strength requirements

  if (this.config.passwordPolicy.patternValidator && !this.config.passwordPolicy.patternValidator(this.data.password) || this.config.passwordPolicy.validatorCallback && !this.config.passwordPolicy.validatorCallback(this.data.password)) {
    return Promise.reject(new Parse.Error(Parse.Error.VALIDATION_ERROR, policyError));
  } // check whether password contain username


  if (this.config.passwordPolicy.doNotAllowUsername === true) {
    if (this.data.username) {
      // username is not passed during password reset
      if (this.data.password.indexOf(this.data.username) >= 0) return Promise.reject(new Parse.Error(Parse.Error.VALIDATION_ERROR, containsUsernameError));
    } else {
      // retrieve the User object using objectId during password reset
      return this.config.database.find('_User', {
        objectId: this.objectId()
      }).then(results => {
        if (results.length != 1) {
          throw undefined;
        }

        if (this.data.password.indexOf(results[0].username) >= 0) return Promise.reject(new Parse.Error(Parse.Error.VALIDATION_ERROR, containsUsernameError));
        return Promise.resolve();
      });
    }
  }

  return Promise.resolve();
};

RestWrite.prototype._validatePasswordHistory = function () {
  // check whether password is repeating from specified history
  if (this.query && this.config.passwordPolicy.maxPasswordHistory) {
    return this.config.database.find('_User', {
      objectId: this.objectId()
    }, {
      keys: ['_password_history', '_hashed_password']
    }).then(results => {
      if (results.length != 1) {
        throw undefined;
      }

      const user = results[0];
      let oldPasswords = [];
      if (user._password_history) oldPasswords = _lodash.default.take(user._password_history, this.config.passwordPolicy.maxPasswordHistory - 1);
      oldPasswords.push(user.password);
      const newPassword = this.data.password; // compare the new password hash with all old password hashes

      const promises = oldPasswords.map(function (hash) {
        return passwordCrypto.compare(newPassword, hash).then(result => {
          if (result) // reject if there is a match
            return Promise.reject('REPEAT_PASSWORD');
          return Promise.resolve();
        });
      }); // wait for all comparisons to complete

      return Promise.all(promises).then(() => {
        return Promise.resolve();
      }).catch(err => {
        if (err === 'REPEAT_PASSWORD') // a match was found
          return Promise.reject(new Parse.Error(Parse.Error.VALIDATION_ERROR, `New password should not be the same as last ${this.config.passwordPolicy.maxPasswordHistory} passwords.`));
        throw err;
      });
    });
  }

  return Promise.resolve();
};

RestWrite.prototype.createSessionTokenIfNeeded = function () {
  if (this.className !== '_User') {
    return;
  } // Don't generate session for updating user (this.query is set) unless authData exists


  if (this.query && !this.data.authData) {
    return;
  } // Don't generate new sessionToken if linking via sessionToken


  if (this.auth.user && this.data.authData) {
    return;
  }

  if (!this.storage['authProvider'] && // signup call, with
  this.config.preventLoginWithUnverifiedEmail && // no login without verification
  this.config.verifyUserEmails) {
    // verification is on
    return; // do not create the session token in that case!
  }

  return this.createSessionToken();
};

RestWrite.prototype.createSessionToken = async function () {
  // cloud installationId from Cloud Code,
  // never create session tokens from there.
  if (this.auth.installationId && this.auth.installationId === 'cloud') {
    return;
  }

  const {
    sessionData,
    createSession
  } = RestWrite.createSession(this.config, {
    userId: this.objectId(),
    createdWith: {
      action: this.storage['authProvider'] ? 'login' : 'signup',
      authProvider: this.storage['authProvider'] || 'password'
    },
    installationId: this.auth.installationId
  });

  if (this.response && this.response.response) {
    this.response.response.sessionToken = sessionData.sessionToken;
  }

  return createSession();
};

RestWrite.createSession = function (config, {
  userId,
  createdWith,
  installationId,
  additionalSessionData
}) {
  const token = 'r:' + cryptoUtils.newToken();
  const expiresAt = config.generateSessionExpiresAt();
  const sessionData = {
    sessionToken: token,
    user: {
      __type: 'Pointer',
      className: '_User',
      objectId: userId
    },
    createdWith,
    restricted: false,
    expiresAt: Parse._encode(expiresAt)
  };

  if (installationId) {
    sessionData.installationId = installationId;
  }

  Object.assign(sessionData, additionalSessionData);
  return {
    sessionData,
    createSession: () => new RestWrite(config, Auth.master(config), '_Session', null, sessionData).execute()
  };
}; // Delete email reset tokens if user is changing password or email.


RestWrite.prototype.deleteEmailResetTokenIfNeeded = function () {
  if (this.className !== '_User' || this.query === null) {
    // null query means create
    return;
  }

  if ('password' in this.data || 'email' in this.data) {
    const addOps = {
      _perishable_token: {
        __op: 'Delete'
      },
      _perishable_token_expires_at: {
        __op: 'Delete'
      }
    };
    this.data = Object.assign(this.data, addOps);
  }
};

RestWrite.prototype.destroyDuplicatedSessions = function () {
  // Only for _Session, and at creation time
  if (this.className != '_Session' || this.query) {
    return;
  } // Destroy the sessions in 'Background'


  const {
    user,
    installationId,
    sessionToken
  } = this.data;

  if (!user || !installationId) {
    return;
  }

  if (!user.objectId) {
    return;
  }

  this.config.database.destroy('_Session', {
    user,
    installationId,
    sessionToken: {
      $ne: sessionToken
    }
  }, {}, this.validSchemaController);
}; // Handles any followup logic


RestWrite.prototype.handleFollowup = function () {
  if (this.storage && this.storage['clearSessions'] && this.config.revokeSessionOnPasswordReset) {
    var sessionQuery = {
      user: {
        __type: 'Pointer',
        className: '_User',
        objectId: this.objectId()
      }
    };
    delete this.storage['clearSessions'];
    return this.config.database.destroy('_Session', sessionQuery).then(this.handleFollowup.bind(this));
  }

  if (this.storage && this.storage['generateNewSession']) {
    delete this.storage['generateNewSession'];
    return this.createSessionToken().then(this.handleFollowup.bind(this));
  }

  if (this.storage && this.storage['sendVerificationEmail']) {
    delete this.storage['sendVerificationEmail']; // Fire and forget!

    this.config.userController.sendVerificationEmail(this.data);
    return this.handleFollowup.bind(this);
  }
}; // Handles the _Session class specialness.
// Does nothing if this isn't an _Session object.


RestWrite.prototype.handleSession = function () {
  if (this.response || this.className !== '_Session') {
    return;
  }

  if (!this.auth.user && !this.auth.isMaster) {
    throw new Parse.Error(Parse.Error.INVALID_SESSION_TOKEN, 'Session token required.');
  } // TODO: Verify proper error to throw


  if (this.data.ACL) {
    throw new Parse.Error(Parse.Error.INVALID_KEY_NAME, 'Cannot set ' + 'ACL on a Session.');
  }

  if (this.query) {
    if (this.data.user && !this.auth.isMaster && this.data.user.objectId != this.auth.user.id) {
      throw new Parse.Error(Parse.Error.INVALID_KEY_NAME);
    } else if (this.data.installationId) {
      throw new Parse.Error(Parse.Error.INVALID_KEY_NAME);
    } else if (this.data.sessionToken) {
      throw new Parse.Error(Parse.Error.INVALID_KEY_NAME);
    }
  }

  if (!this.query && !this.auth.isMaster) {
    const additionalSessionData = {};

    for (var key in this.data) {
      if (key === 'objectId' || key === 'user') {
        continue;
      }

      additionalSessionData[key] = this.data[key];
    }

    const {
      sessionData,
      createSession
    } = RestWrite.createSession(this.config, {
      userId: this.auth.user.id,
      createdWith: {
        action: 'create'
      },
      additionalSessionData
    });
    return createSession().then(results => {
      if (!results.response) {
        throw new Parse.Error(Parse.Error.INTERNAL_SERVER_ERROR, 'Error creating session.');
      }

      sessionData['objectId'] = results.response['objectId'];
      this.response = {
        status: 201,
        location: results.location,
        response: sessionData
      };
    });
  }
}; // Handles the _Installation class specialness.
// Does nothing if this isn't an installation object.
// If an installation is found, this can mutate this.query and turn a create
// into an update.
// Returns a promise for when we're done if it can't finish this tick.


RestWrite.prototype.handleInstallation = function () {
  if (this.response || this.className !== '_Installation') {
    return;
  }

  if (!this.query && !this.data.deviceToken && !this.data.installationId && !this.auth.installationId) {
    throw new Parse.Error(135, 'at least one ID field (deviceToken, installationId) ' + 'must be specified in this operation');
  } // If the device token is 64 characters long, we assume it is for iOS
  // and lowercase it.


  if (this.data.deviceToken && this.data.deviceToken.length == 64) {
    this.data.deviceToken = this.data.deviceToken.toLowerCase();
  } // We lowercase the installationId if present


  if (this.data.installationId) {
    this.data.installationId = this.data.installationId.toLowerCase();
  }

  let installationId = this.data.installationId; // If data.installationId is not set and we're not master, we can lookup in auth

  if (!installationId && !this.auth.isMaster) {
    installationId = this.auth.installationId;
  }

  if (installationId) {
    installationId = installationId.toLowerCase();
  } // Updating _Installation but not updating anything critical


  if (this.query && !this.data.deviceToken && !installationId && !this.data.deviceType) {
    return;
  }

  var promise = Promise.resolve();
  var idMatch; // Will be a match on either objectId or installationId

  var objectIdMatch;
  var installationIdMatch;
  var deviceTokenMatches = []; // Instead of issuing 3 reads, let's do it with one OR.

  const orQueries = [];

  if (this.query && this.query.objectId) {
    orQueries.push({
      objectId: this.query.objectId
    });
  }

  if (installationId) {
    orQueries.push({
      installationId: installationId
    });
  }

  if (this.data.deviceToken) {
    orQueries.push({
      deviceToken: this.data.deviceToken
    });
  }

  if (orQueries.length == 0) {
    return;
  }

  promise = promise.then(() => {
    return this.config.database.find('_Installation', {
      $or: orQueries
    }, {});
  }).then(results => {
    results.forEach(result => {
      if (this.query && this.query.objectId && result.objectId == this.query.objectId) {
        objectIdMatch = result;
      }

      if (result.installationId == installationId) {
        installationIdMatch = result;
      }

      if (result.deviceToken == this.data.deviceToken) {
        deviceTokenMatches.push(result);
      }
    }); // Sanity checks when running a query

    if (this.query && this.query.objectId) {
      if (!objectIdMatch) {
        throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Object not found for update.');
      }

      if (this.data.installationId && objectIdMatch.installationId && this.data.installationId !== objectIdMatch.installationId) {
        throw new Parse.Error(136, 'installationId may not be changed in this ' + 'operation');
      }

      if (this.data.deviceToken && objectIdMatch.deviceToken && this.data.deviceToken !== objectIdMatch.deviceToken && !this.data.installationId && !objectIdMatch.installationId) {
        throw new Parse.Error(136, 'deviceToken may not be changed in this ' + 'operation');
      }

      if (this.data.deviceType && this.data.deviceType && this.data.deviceType !== objectIdMatch.deviceType) {
        throw new Parse.Error(136, 'deviceType may not be changed in this ' + 'operation');
      }
    }

    if (this.query && this.query.objectId && objectIdMatch) {
      idMatch = objectIdMatch;
    }

    if (installationId && installationIdMatch) {
      idMatch = installationIdMatch;
    } // need to specify deviceType only if it's new


    if (!this.query && !this.data.deviceType && !idMatch) {
      throw new Parse.Error(135, 'deviceType must be specified in this operation');
    }
  }).then(() => {
    if (!idMatch) {
      if (!deviceTokenMatches.length) {
        return;
      } else if (deviceTokenMatches.length == 1 && (!deviceTokenMatches[0]['installationId'] || !installationId)) {
        // Single match on device token but none on installationId, and either
        // the passed object or the match is missing an installationId, so we
        // can just return the match.
        return deviceTokenMatches[0]['objectId'];
      } else if (!this.data.installationId) {
        throw new Parse.Error(132, 'Must specify installationId when deviceToken ' + 'matches multiple Installation objects');
      } else {
        // Multiple device token matches and we specified an installation ID,
        // or a single match where both the passed and matching objects have
        // an installation ID. Try cleaning out old installations that match
        // the deviceToken, and return nil to signal that a new object should
        // be created.
        var delQuery = {
          deviceToken: this.data.deviceToken,
          installationId: {
            $ne: installationId
          }
        };

        if (this.data.appIdentifier) {
          delQuery['appIdentifier'] = this.data.appIdentifier;
        }

        this.config.database.destroy('_Installation', delQuery).catch(err => {
          if (err.code == Parse.Error.OBJECT_NOT_FOUND) {
            // no deletions were made. Can be ignored.
            return;
          } // rethrow the error


          throw err;
        });
        return;
      }
    } else {
      if (deviceTokenMatches.length == 1 && !deviceTokenMatches[0]['installationId']) {
        // Exactly one device token match and it doesn't have an installation
        // ID. This is the one case where we want to merge with the existing
        // object.
        const delQuery = {
          objectId: idMatch.objectId
        };
        return this.config.database.destroy('_Installation', delQuery).then(() => {
          return deviceTokenMatches[0]['objectId'];
        }).catch(err => {
          if (err.code == Parse.Error.OBJECT_NOT_FOUND) {
            // no deletions were made. Can be ignored
            return;
          } // rethrow the error


          throw err;
        });
      } else {
        if (this.data.deviceToken && idMatch.deviceToken != this.data.deviceToken) {
          // We're setting the device token on an existing installation, so
          // we should try cleaning out old installations that match this
          // device token.
          const delQuery = {
            deviceToken: this.data.deviceToken
          }; // We have a unique install Id, use that to preserve
          // the interesting installation

          if (this.data.installationId) {
            delQuery['installationId'] = {
              $ne: this.data.installationId
            };
          } else if (idMatch.objectId && this.data.objectId && idMatch.objectId == this.data.objectId) {
            // we passed an objectId, preserve that instalation
            delQuery['objectId'] = {
              $ne: idMatch.objectId
            };
          } else {
            // What to do here? can't really clean up everything...
            return idMatch.objectId;
          }

          if (this.data.appIdentifier) {
            delQuery['appIdentifier'] = this.data.appIdentifier;
          }

          this.config.database.destroy('_Installation', delQuery).catch(err => {
            if (err.code == Parse.Error.OBJECT_NOT_FOUND) {
              // no deletions were made. Can be ignored.
              return;
            } // rethrow the error


            throw err;
          });
        } // In non-merge scenarios, just return the installation match id


        return idMatch.objectId;
      }
    }
  }).then(objId => {
    if (objId) {
      this.query = {
        objectId: objId
      };
      delete this.data.objectId;
      delete this.data.createdAt;
    } // TODO: Validate ops (add/remove on channels, $inc on badge, etc.)

  });
  return promise;
}; // If we short-circuited the object response - then we need to make sure we expand all the files,
// since this might not have a query, meaning it won't return the full result back.
// TODO: (nlutsenko) This should die when we move to per-class based controllers on _Session/_User


RestWrite.prototype.expandFilesForExistingObjects = function () {
  // Check whether we have a short-circuited response - only then run expansion.
  if (this.response && this.response.response) {
    this.config.filesController.expandFilesInObject(this.config, this.response.response);
  }
};

RestWrite.prototype.runDatabaseOperation = function () {
  if (this.response) {
    return;
  }

  if (this.className === '_Role') {
    this.config.cacheController.role.clear();
  }

  if (this.className === '_User' && this.query && this.auth.isUnauthenticated()) {
    throw new Parse.Error(Parse.Error.SESSION_MISSING, `Cannot modify user ${this.query.objectId}.`);
  }

  if (this.className === '_Product' && this.data.download) {
    this.data.downloadName = this.data.download.name;
  } // TODO: Add better detection for ACL, ensuring a user can't be locked from
  //       their own user record.


  if (this.data.ACL && this.data.ACL['*unresolved']) {
    throw new Parse.Error(Parse.Error.INVALID_ACL, 'Invalid ACL.');
  }

  if (this.query) {
    // Force the user to not lockout
    // Matched with parse.com
    if (this.className === '_User' && this.data.ACL && this.auth.isMaster !== true) {
      this.data.ACL[this.query.objectId] = {
        read: true,
        write: true
      };
    } // update password timestamp if user password is being changed


    if (this.className === '_User' && this.data._hashed_password && this.config.passwordPolicy && this.config.passwordPolicy.maxPasswordAge) {
      this.data._password_changed_at = Parse._encode(new Date());
    } // Ignore createdAt when update


    delete this.data.createdAt;
    let defer = Promise.resolve(); // if password history is enabled then save the current password to history

    if (this.className === '_User' && this.data._hashed_password && this.config.passwordPolicy && this.config.passwordPolicy.maxPasswordHistory) {
      defer = this.config.database.find('_User', {
        objectId: this.objectId()
      }, {
        keys: ['_password_history', '_hashed_password']
      }).then(results => {
        if (results.length != 1) {
          throw undefined;
        }

        const user = results[0];
        let oldPasswords = [];

        if (user._password_history) {
          oldPasswords = _lodash.default.take(user._password_history, this.config.passwordPolicy.maxPasswordHistory);
        } //n-1 passwords go into history including last password


        while (oldPasswords.length > Math.max(0, this.config.passwordPolicy.maxPasswordHistory - 2)) {
          oldPasswords.shift();
        }

        oldPasswords.push(user.password);
        this.data._password_history = oldPasswords;
      });
    }

    return defer.then(() => {
      // Run an update
      return this.config.database.update(this.className, this.query, this.data, this.runOptions, false, false, this.validSchemaController).then(response => {
        response.updatedAt = this.updatedAt;

        this._updateResponseWithData(response, this.data);

        this.response = {
          response
        };
      });
    });
  } else {
    // Set the default ACL and password timestamp for the new _User
    if (this.className === '_User') {
      var ACL = this.data.ACL; // default public r/w ACL

      if (!ACL) {
        ACL = {};
        ACL['*'] = {
          read: true,
          write: false
        };
      } // make sure the user is not locked down


      ACL[this.data.objectId] = {
        read: true,
        write: true
      };
      this.data.ACL = ACL; // password timestamp to be used when password expiry policy is enforced

      if (this.config.passwordPolicy && this.config.passwordPolicy.maxPasswordAge) {
        this.data._password_changed_at = Parse._encode(new Date());
      }
    } // Run a create


    return this.config.database.create(this.className, this.data, this.runOptions, false, this.validSchemaController).catch(error => {
      if (this.className !== '_User' || error.code !== Parse.Error.DUPLICATE_VALUE) {
        throw error;
      } // Quick check, if we were able to infer the duplicated field name


      if (error && error.userInfo && error.userInfo.duplicated_field === 'username') {
        throw new Parse.Error(Parse.Error.USERNAME_TAKEN, 'Account already exists for this username.');
      }

      if (error && error.userInfo && error.userInfo.duplicated_field === 'email') {
        throw new Parse.Error(Parse.Error.EMAIL_TAKEN, 'Account already exists for this email address.');
      } // If this was a failed user creation due to username or email already taken, we need to
      // check whether it was username or email and return the appropriate error.
      // Fallback to the original method
      // TODO: See if we can later do this without additional queries by using named indexes.


      return this.config.database.find(this.className, {
        username: this.data.username,
        objectId: {
          $ne: this.objectId()
        }
      }, {
        limit: 1
      }).then(results => {
        if (results.length > 0) {
          throw new Parse.Error(Parse.Error.USERNAME_TAKEN, 'Account already exists for this username.');
        }

        return this.config.database.find(this.className, {
          email: this.data.email,
          objectId: {
            $ne: this.objectId()
          }
        }, {
          limit: 1
        });
      }).then(results => {
        if (results.length > 0) {
          throw new Parse.Error(Parse.Error.EMAIL_TAKEN, 'Account already exists for this email address.');
        }

        throw new Parse.Error(Parse.Error.DUPLICATE_VALUE, 'A duplicate value for a field with unique values was provided');
      });
    }).then(response => {
      response.objectId = this.data.objectId;
      response.createdAt = this.data.createdAt;

      if (this.responseShouldHaveUsername) {
        response.username = this.data.username;
      }

      this._updateResponseWithData(response, this.data);

      this.response = {
        status: 201,
        response,
        location: this.location()
      };
    });
  }
}; // Returns nothing - doesn't wait for the trigger.


RestWrite.prototype.runAfterSaveTrigger = function () {
  if (!this.response || !this.response.response) {
    return;
  } // Avoid doing any setup for triggers if there is no 'afterSave' trigger for this class.


  const hasAfterSaveHook = triggers.triggerExists(this.className, triggers.Types.afterSave, this.config.applicationId);
  const hasLiveQuery = this.config.liveQueryController.hasLiveQuery(this.className);

  if (!hasAfterSaveHook && !hasLiveQuery) {
    return Promise.resolve();
  }

  var extraData = {
    className: this.className
  };

  if (this.query && this.query.objectId) {
    extraData.objectId = this.query.objectId;
  } // Build the original object, we only do this for a update write.


  let originalObject;

  if (this.query && this.query.objectId) {
    originalObject = triggers.inflate(extraData, this.originalData);
  } // Build the inflated object, different from beforeSave, originalData is not empty
  // since developers can change data in the beforeSave.


  const updatedObject = this.buildUpdatedObject(extraData);

  updatedObject._handleSaveResponse(this.response.response, this.response.status || 200);

  this.config.database.loadSchema().then(schemaController => {
    // Notifiy LiveQueryServer if possible
    const perms = schemaController.getClassLevelPermissions(updatedObject.className);
    this.config.liveQueryController.onAfterSave(updatedObject.className, updatedObject, originalObject, perms);
  }); // Run afterSave trigger

  return triggers.maybeRunTrigger(triggers.Types.afterSave, this.auth, updatedObject, originalObject, this.config, this.context).then(result => {
    if (result && typeof result === 'object') {
      this.response.response = result;
    }
  }).catch(function (err) {
    _logger.default.warn('afterSave caught an error', err);
  });
}; // A helper to figure out what location this operation happens at.


RestWrite.prototype.location = function () {
  var middle = this.className === '_User' ? '/users/' : '/classes/' + this.className + '/';
  const mount = this.config.mount || this.config.serverURL;
  return mount + middle + this.data.objectId;
}; // A helper to get the object id for this operation.
// Because it could be either on the query or on the data


RestWrite.prototype.objectId = function () {
  return this.data.objectId || this.query.objectId;
}; // Returns a copy of the data and delete bad keys (_auth_data, _hashed_password...)


RestWrite.prototype.sanitizedData = function () {
  const data = Object.keys(this.data).reduce((data, key) => {
    // Regexp comes from Parse.Object.prototype.validate
    if (!/^[A-Za-z][0-9A-Za-z_]*$/.test(key)) {
      delete data[key];
    }

    return data;
  }, deepcopy(this.data));
  return Parse._decode(undefined, data);
}; // Returns an updated copy of the object


RestWrite.prototype.buildUpdatedObject = function (extraData) {
  const updatedObject = triggers.inflate(extraData, this.originalData);
  Object.keys(this.data).reduce(function (data, key) {
    if (key.indexOf('.') > 0) {
      if (typeof data[key].__op === 'string') {
        updatedObject.set(key, data[key]);
      } else {
        // subdocument key with dot notation { 'x.y': v } => { 'x': { 'y' : v } })
        const splittedKey = key.split('.');
        const parentProp = splittedKey[0];
        let parentVal = updatedObject.get(parentProp);

        if (typeof parentVal !== 'object') {
          parentVal = {};
        }

        parentVal[splittedKey[1]] = data[key];
        updatedObject.set(parentProp, parentVal);
      }

      delete data[key];
    }

    return data;
  }, deepcopy(this.data));
  updatedObject.set(this.sanitizedData());
  return updatedObject;
};

RestWrite.prototype.cleanUserAuthData = function () {
  if (this.response && this.response.response && this.className === '_User') {
    const user = this.response.response;

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
  }
};

RestWrite.prototype._updateResponseWithData = function (response, data) {
  if (_lodash.default.isEmpty(this.storage.fieldsChangedByTrigger)) {
    return response;
  }

  const clientSupportsDelete = ClientSDK.supportsForwardDelete(this.clientSDK);
  this.storage.fieldsChangedByTrigger.forEach(fieldName => {
    const dataValue = data[fieldName];

    if (!Object.prototype.hasOwnProperty.call(response, fieldName)) {
      response[fieldName] = dataValue;
    } // Strips operations from responses


    if (response[fieldName] && response[fieldName].__op) {
      delete response[fieldName];

      if (clientSupportsDelete && dataValue.__op == 'Delete') {
        response[fieldName] = dataValue;
      }
    }
  });
  return response;
};

var _default = RestWrite;
exports.default = _default;
module.exports = RestWrite;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9SZXN0V3JpdGUuanMiXSwibmFtZXMiOlsiU2NoZW1hQ29udHJvbGxlciIsInJlcXVpcmUiLCJkZWVwY29weSIsIkF1dGgiLCJjcnlwdG9VdGlscyIsInBhc3N3b3JkQ3J5cHRvIiwiUGFyc2UiLCJ0cmlnZ2VycyIsIkNsaWVudFNESyIsIlJlc3RXcml0ZSIsImNvbmZpZyIsImF1dGgiLCJjbGFzc05hbWUiLCJxdWVyeSIsImRhdGEiLCJvcmlnaW5hbERhdGEiLCJjbGllbnRTREsiLCJjb250ZXh0IiwiYWN0aW9uIiwiaXNSZWFkT25seSIsIkVycm9yIiwiT1BFUkFUSU9OX0ZPUkJJRERFTiIsInN0b3JhZ2UiLCJydW5PcHRpb25zIiwiYWxsb3dDdXN0b21PYmplY3RJZCIsIk9iamVjdCIsInByb3RvdHlwZSIsImhhc093blByb3BlcnR5IiwiY2FsbCIsIm9iamVjdElkIiwiTUlTU0lOR19PQkpFQ1RfSUQiLCJJTlZBTElEX0tFWV9OQU1FIiwiaWQiLCJyZXNwb25zZSIsInVwZGF0ZWRBdCIsIl9lbmNvZGUiLCJEYXRlIiwiaXNvIiwidmFsaWRTY2hlbWFDb250cm9sbGVyIiwiZXhlY3V0ZSIsIlByb21pc2UiLCJyZXNvbHZlIiwidGhlbiIsImdldFVzZXJBbmRSb2xlQUNMIiwidmFsaWRhdGVDbGllbnRDbGFzc0NyZWF0aW9uIiwiaGFuZGxlSW5zdGFsbGF0aW9uIiwiaGFuZGxlU2Vzc2lvbiIsInZhbGlkYXRlQXV0aERhdGEiLCJydW5CZWZvcmVTYXZlVHJpZ2dlciIsImRlbGV0ZUVtYWlsUmVzZXRUb2tlbklmTmVlZGVkIiwidmFsaWRhdGVTY2hlbWEiLCJzY2hlbWFDb250cm9sbGVyIiwic2V0UmVxdWlyZWRGaWVsZHNJZk5lZWRlZCIsInRyYW5zZm9ybVVzZXIiLCJleHBhbmRGaWxlc0ZvckV4aXN0aW5nT2JqZWN0cyIsImRlc3Ryb3lEdXBsaWNhdGVkU2Vzc2lvbnMiLCJydW5EYXRhYmFzZU9wZXJhdGlvbiIsImNyZWF0ZVNlc3Npb25Ub2tlbklmTmVlZGVkIiwiaGFuZGxlRm9sbG93dXAiLCJydW5BZnRlclNhdmVUcmlnZ2VyIiwiY2xlYW5Vc2VyQXV0aERhdGEiLCJpc01hc3RlciIsImFjbCIsInVzZXIiLCJnZXRVc2VyUm9sZXMiLCJyb2xlcyIsImNvbmNhdCIsImFsbG93Q2xpZW50Q2xhc3NDcmVhdGlvbiIsInN5c3RlbUNsYXNzZXMiLCJpbmRleE9mIiwiZGF0YWJhc2UiLCJsb2FkU2NoZW1hIiwiaGFzQ2xhc3MiLCJ2YWxpZGF0ZU9iamVjdCIsInRyaWdnZXJFeGlzdHMiLCJUeXBlcyIsImJlZm9yZVNhdmUiLCJhcHBsaWNhdGlvbklkIiwiZXh0cmFEYXRhIiwib3JpZ2luYWxPYmplY3QiLCJ1cGRhdGVkT2JqZWN0IiwiYnVpbGRVcGRhdGVkT2JqZWN0IiwiaW5mbGF0ZSIsImRhdGFiYXNlUHJvbWlzZSIsInVwZGF0ZSIsImNyZWF0ZSIsInJlc3VsdCIsImxlbmd0aCIsIk9CSkVDVF9OT1RfRk9VTkQiLCJtYXliZVJ1blRyaWdnZXIiLCJvYmplY3QiLCJmaWVsZHNDaGFuZ2VkQnlUcmlnZ2VyIiwiXyIsInJlZHVjZSIsInZhbHVlIiwia2V5IiwiaXNFcXVhbCIsInB1c2giLCJydW5CZWZvcmVMb2dpblRyaWdnZXIiLCJ1c2VyRGF0YSIsImJlZm9yZUxvZ2luIiwiZmlsZXNDb250cm9sbGVyIiwiZXhwYW5kRmlsZXNJbk9iamVjdCIsImdldEFsbENsYXNzZXMiLCJhbGxDbGFzc2VzIiwic2NoZW1hIiwiZmluZCIsIm9uZUNsYXNzIiwic2V0UmVxdWlyZWRGaWVsZElmTmVlZGVkIiwiZmllbGROYW1lIiwic2V0RGVmYXVsdCIsInVuZGVmaW5lZCIsIl9fb3AiLCJmaWVsZHMiLCJkZWZhdWx0VmFsdWUiLCJyZXF1aXJlZCIsIlZBTElEQVRJT05fRVJST1IiLCJjcmVhdGVkQXQiLCJuZXdPYmplY3RJZCIsIm9iamVjdElkU2l6ZSIsImtleXMiLCJmb3JFYWNoIiwiYXV0aERhdGEiLCJ1c2VybmFtZSIsImlzRW1wdHkiLCJVU0VSTkFNRV9NSVNTSU5HIiwicGFzc3dvcmQiLCJQQVNTV09SRF9NSVNTSU5HIiwiVU5TVVBQT1JURURfU0VSVklDRSIsInByb3ZpZGVycyIsImNhbkhhbmRsZUF1dGhEYXRhIiwiY2FuSGFuZGxlIiwicHJvdmlkZXIiLCJwcm92aWRlckF1dGhEYXRhIiwiaGFzVG9rZW4iLCJoYW5kbGVBdXRoRGF0YSIsImhhbmRsZUF1dGhEYXRhVmFsaWRhdGlvbiIsInZhbGlkYXRpb25zIiwibWFwIiwiYXV0aERhdGFNYW5hZ2VyIiwiZ2V0VmFsaWRhdG9yRm9yUHJvdmlkZXIiLCJhbGwiLCJmaW5kVXNlcnNXaXRoQXV0aERhdGEiLCJtZW1vIiwicXVlcnlLZXkiLCJmaWx0ZXIiLCJxIiwiZmluZFByb21pc2UiLCIkb3IiLCJmaWx0ZXJlZE9iamVjdHNCeUFDTCIsIm9iamVjdHMiLCJBQ0wiLCJyZXN1bHRzIiwiciIsImpvaW4iLCJ1c2VyUmVzdWx0IiwibXV0YXRlZEF1dGhEYXRhIiwicHJvdmlkZXJEYXRhIiwidXNlckF1dGhEYXRhIiwiaGFzTXV0YXRlZEF1dGhEYXRhIiwidXNlcklkIiwibG9jYXRpb24iLCJBQ0NPVU5UX0FMUkVBRFlfTElOS0VEIiwicHJvbWlzZSIsImVycm9yIiwiUmVzdFF1ZXJ5IiwibWFzdGVyIiwiX190eXBlIiwic2Vzc2lvbiIsImNhY2hlQ29udHJvbGxlciIsImRlbCIsInNlc3Npb25Ub2tlbiIsIl92YWxpZGF0ZVBhc3N3b3JkUG9saWN5IiwiaGFzaCIsImhhc2hlZFBhc3N3b3JkIiwiX2hhc2hlZF9wYXNzd29yZCIsIl92YWxpZGF0ZVVzZXJOYW1lIiwiX3ZhbGlkYXRlRW1haWwiLCJyYW5kb21TdHJpbmciLCJyZXNwb25zZVNob3VsZEhhdmVVc2VybmFtZSIsIiRuZSIsImxpbWl0IiwiY2FzZUluc2Vuc2l0aXZlIiwiVVNFUk5BTUVfVEFLRU4iLCJlbWFpbCIsIm1hdGNoIiwicmVqZWN0IiwiSU5WQUxJRF9FTUFJTF9BRERSRVNTIiwiRU1BSUxfVEFLRU4iLCJ1c2VyQ29udHJvbGxlciIsInNldEVtYWlsVmVyaWZ5VG9rZW4iLCJwYXNzd29yZFBvbGljeSIsIl92YWxpZGF0ZVBhc3N3b3JkUmVxdWlyZW1lbnRzIiwiX3ZhbGlkYXRlUGFzc3dvcmRIaXN0b3J5IiwicG9saWN5RXJyb3IiLCJ2YWxpZGF0aW9uRXJyb3IiLCJjb250YWluc1VzZXJuYW1lRXJyb3IiLCJwYXR0ZXJuVmFsaWRhdG9yIiwidmFsaWRhdG9yQ2FsbGJhY2siLCJkb05vdEFsbG93VXNlcm5hbWUiLCJtYXhQYXNzd29yZEhpc3RvcnkiLCJvbGRQYXNzd29yZHMiLCJfcGFzc3dvcmRfaGlzdG9yeSIsInRha2UiLCJuZXdQYXNzd29yZCIsInByb21pc2VzIiwiY29tcGFyZSIsImNhdGNoIiwiZXJyIiwicHJldmVudExvZ2luV2l0aFVudmVyaWZpZWRFbWFpbCIsInZlcmlmeVVzZXJFbWFpbHMiLCJjcmVhdGVTZXNzaW9uVG9rZW4iLCJpbnN0YWxsYXRpb25JZCIsInNlc3Npb25EYXRhIiwiY3JlYXRlU2Vzc2lvbiIsImNyZWF0ZWRXaXRoIiwiYXV0aFByb3ZpZGVyIiwiYWRkaXRpb25hbFNlc3Npb25EYXRhIiwidG9rZW4iLCJuZXdUb2tlbiIsImV4cGlyZXNBdCIsImdlbmVyYXRlU2Vzc2lvbkV4cGlyZXNBdCIsInJlc3RyaWN0ZWQiLCJhc3NpZ24iLCJhZGRPcHMiLCJfcGVyaXNoYWJsZV90b2tlbiIsIl9wZXJpc2hhYmxlX3Rva2VuX2V4cGlyZXNfYXQiLCJkZXN0cm95IiwicmV2b2tlU2Vzc2lvbk9uUGFzc3dvcmRSZXNldCIsInNlc3Npb25RdWVyeSIsImJpbmQiLCJzZW5kVmVyaWZpY2F0aW9uRW1haWwiLCJJTlZBTElEX1NFU1NJT05fVE9LRU4iLCJJTlRFUk5BTF9TRVJWRVJfRVJST1IiLCJzdGF0dXMiLCJkZXZpY2VUb2tlbiIsInRvTG93ZXJDYXNlIiwiZGV2aWNlVHlwZSIsImlkTWF0Y2giLCJvYmplY3RJZE1hdGNoIiwiaW5zdGFsbGF0aW9uSWRNYXRjaCIsImRldmljZVRva2VuTWF0Y2hlcyIsIm9yUXVlcmllcyIsImRlbFF1ZXJ5IiwiYXBwSWRlbnRpZmllciIsImNvZGUiLCJvYmpJZCIsInJvbGUiLCJjbGVhciIsImlzVW5hdXRoZW50aWNhdGVkIiwiU0VTU0lPTl9NSVNTSU5HIiwiZG93bmxvYWQiLCJkb3dubG9hZE5hbWUiLCJuYW1lIiwiSU5WQUxJRF9BQ0wiLCJyZWFkIiwid3JpdGUiLCJtYXhQYXNzd29yZEFnZSIsIl9wYXNzd29yZF9jaGFuZ2VkX2F0IiwiZGVmZXIiLCJNYXRoIiwibWF4Iiwic2hpZnQiLCJfdXBkYXRlUmVzcG9uc2VXaXRoRGF0YSIsIkRVUExJQ0FURV9WQUxVRSIsInVzZXJJbmZvIiwiZHVwbGljYXRlZF9maWVsZCIsImhhc0FmdGVyU2F2ZUhvb2siLCJhZnRlclNhdmUiLCJoYXNMaXZlUXVlcnkiLCJsaXZlUXVlcnlDb250cm9sbGVyIiwiX2hhbmRsZVNhdmVSZXNwb25zZSIsInBlcm1zIiwiZ2V0Q2xhc3NMZXZlbFBlcm1pc3Npb25zIiwib25BZnRlclNhdmUiLCJsb2dnZXIiLCJ3YXJuIiwibWlkZGxlIiwibW91bnQiLCJzZXJ2ZXJVUkwiLCJzYW5pdGl6ZWREYXRhIiwidGVzdCIsIl9kZWNvZGUiLCJzZXQiLCJzcGxpdHRlZEtleSIsInNwbGl0IiwicGFyZW50UHJvcCIsInBhcmVudFZhbCIsImdldCIsImNsaWVudFN1cHBvcnRzRGVsZXRlIiwic3VwcG9ydHNGb3J3YXJkRGVsZXRlIiwiZGF0YVZhbHVlIiwibW9kdWxlIiwiZXhwb3J0cyJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQWFBOztBQUNBOztBQUNBOzs7O0FBZkE7QUFDQTtBQUNBO0FBRUEsSUFBSUEsZ0JBQWdCLEdBQUdDLE9BQU8sQ0FBQyxnQ0FBRCxDQUE5Qjs7QUFDQSxJQUFJQyxRQUFRLEdBQUdELE9BQU8sQ0FBQyxVQUFELENBQXRCOztBQUVBLE1BQU1FLElBQUksR0FBR0YsT0FBTyxDQUFDLFFBQUQsQ0FBcEI7O0FBQ0EsSUFBSUcsV0FBVyxHQUFHSCxPQUFPLENBQUMsZUFBRCxDQUF6Qjs7QUFDQSxJ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RSxzQkFBdkIsQ0FBSixFQUFvRDtBQUNsRCxXQUFPMUQsUUFBUDtBQUNEOztBQUNELFFBQU1nUSxvQkFBb0IsR0FBR3pSLFNBQVMsQ0FBQzBSLHFCQUFWLENBQWdDLEtBQUtsUixTQUFyQyxDQUE3QjtBQUNBLE9BQUtNLE9BQUwsQ0FBYXFFLHNCQUFiLENBQW9DOEIsT0FBcEMsQ0FBNENaLFNBQVMsSUFBSTtBQUN2RCxVQUFNc0wsU0FBUyxHQUFHclIsSUFBSSxDQUFDK0YsU0FBRCxDQUF0Qjs7QUFFQSxRQUFJLENBQUNwRixNQUFNLENBQUNDLFNBQVAsQ0FBaUJDLGNBQWpCLENBQWdDQyxJQUFoQyxDQUFxQ0ssUUFBckMsRUFBK0M0RSxTQUEvQyxDQUFMLEVBQWdFO0FBQzlENUUsTUFBQUEsUUFBUSxDQUFDNEUsU0FBRCxDQUFSLEdBQXNCc0wsU0FBdEI7QUFDRCxLQUxzRCxDQU92RDs7O0FBQ0EsUUFBSWxRLFFBQVEsQ0FBQzRFLFNBQUQsQ0FBUixJQUF1QjVFLFFBQVEsQ0FBQzRFLFNBQUQsQ0FBUixDQUFvQkcsSUFBL0MsRUFBcUQ7QUFDbkQsYUFBTy9FLFFBQVEsQ0FBQzRFLFNBQUQsQ0FBZjs7QUFDQSxVQUFJb0wsb0JBQW9CLElBQUlFLFNBQVMsQ0FBQ25MLElBQVYsSUFBa0IsUUFBOUMsRUFBd0Q7QUFDdEQvRSxRQUFBQSxRQUFRLENBQUM0RSxTQUFELENBQVIsR0FBc0JzTCxTQUF0QjtBQUNEO0FBQ0Y7QUFDRixHQWREO0FBZUEsU0FBT2xRLFFBQVA7QUFDRCxDQXJCRDs7ZUF1QmV4QixTOztBQUNmMlIsTUFBTSxDQUFDQyxPQUFQLEdBQWlCNVIsU0FBakIiLCJzb3VyY2VzQ29udGVudCI6WyIvLyBBIFJlc3RXcml0ZSBlbmNhcHN1bGF0ZXMgZXZlcnl0aGluZyB3ZSBuZWVkIHRvIHJ1biBhbiBvcGVyYXRpb25cbi8vIHRoYXQgd3JpdGVzIHRvIHRoZSBkYXRhYmFzZS5cbi8vIFRoaXMgY291bGQgYmUgZWl0aGVyIGEgXCJjcmVhdGVcIiBvciBhbiBcInVwZGF0ZVwiLlxuXG52YXIgU2NoZW1hQ29udHJvbGxlciA9IHJlcXVpcmUoJy4vQ29udHJvbGxlcnMvU2NoZW1hQ29udHJvbGxlcicpO1xudmFyIGRlZXBjb3B5ID0gcmVxdWlyZSgnZGVlcGNvcHknKTtcblxuY29uc3QgQXV0aCA9IHJlcXVpcmUoJy4vQXV0aCcpO1xudmFyIGNyeXB0b1V0aWxzID0gcmVxdWlyZSgnLi9jcnlwdG9VdGlscycpO1xudmFyIHBhc3N3b3JkQ3J5cHRvID0gcmVxdWlyZSgnLi9wYXNzd29yZCcpO1xudmFyIFBhcnNlID0gcmVxdWlyZSgncGFyc2Uvbm9kZScpO1xudmFyIHRyaWdnZXJzID0gcmVxdWlyZSgnLi90cmlnZ2VycycpO1xudmFyIENsaWVudFNESyA9IHJlcXVpcmUoJy4vQ2xpZW50U0RLJyk7XG5pbXBvcnQgUmVzdFF1ZXJ5IGZyb20gJy4vUmVzdFF1ZXJ5JztcbmltcG9ydCBfIGZyb20gJ2xvZGFzaCc7XG5pbXBvcnQgbG9nZ2VyIGZyb20gJy4vbG9nZ2VyJztcblxuLy8gcXVlcnkgYW5kIGRhdGEgYXJlIGJvdGggcHJvdmlkZWQgaW4gUkVTVCBBUEkgZm9ybWF0LiBTbyBkYXRhXG4vLyB0eXBlcyBhcmUgZW5jb2RlZCBieSBwbGFpbiBvbGQgb2JqZWN0cy5cbi8vIElmIHF1ZXJ5IGlzIG51bGwsIHRoaXMgaXMgYSBcImNyZWF0ZVwiIGFuZCB0aGUgZGF0YSBpbiBkYXRhIHNob3VsZCBiZVxuLy8gY3JlYXRlZC5cbi8vIE90aGVyd2lzZSB0aGlzIGlzIGFuIFwidXBkYXRlXCIgLSB0aGUgb2JqZWN0IG1hdGNoaW5nIHRoZSBxdWVyeVxuLy8gc2hvdWxkIGdldCB1cGRhdGVkIHdpdGggZGF0YS5cbi8vIFJlc3RXcml0ZSB3aWxsIGhhbmRsZSBvYmplY3RJZCwgY3JlYXRlZEF0LCBhbmQgdXBkYXRlZEF0IGZvclxuLy8gZXZlcnl0aGluZy4gSXQgYWxzbyBrbm93cyB0byB1c2UgdHJpZ2dlcnMgYW5kIHNwZWNpYWwgbW9kaWZpY2F0aW9uc1xuLy8gZm9yIHRoZSBfVXNlciBjbGFzcy5cbmZ1bmN0aW9uIFJlc3RXcml0ZShjb25maWcsIGF1dGgsIGNsYXNzTmFtZSwgcXVlcnksIGRhdGEsIG9yaWdpbmFsRGF0YSwgY2xpZW50U0RLLCBjb250ZXh0LCBhY3Rpb24pIHtcbiAgaWYgKGF1dGguaXNSZWFkT25seSkge1xuICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgIFBhcnNlLkVycm9yLk9QRVJBVElPTl9GT1JCSURERU4sXG4gICAgICAnQ2Fubm90IHBlcmZvcm0gYSB3cml0ZSBvcGVyYXRpb24gd2hlbiB1c2luZyByZWFkT25seU1hc3RlcktleSdcbiAgICApO1xuICB9XG4gIHRoaXMuY29uZmlnID0gY29uZmlnO1xuICB0aGlzLmF1dGggPSBhdXRoO1xuICB0aGlzLmNsYXNzTmFtZSA9IGNsYXNzTmFtZTtcbiAgdGhpcy5jbGllbnRTREsgPSBjbGllbnRTREs7XG4gIHRoaXMuc3RvcmFnZSA9IHt9O1xuICB0aGlzLnJ1bk9wdGlvbnMgPSB7fTtcbiAgdGhpcy5jb250ZXh0ID0gY29udGV4dCB8fCB7fTtcblxuICBpZiAoYWN0aW9uKSB7XG4gICAgdGhpcy5ydW5PcHRpb25zLmFjdGlvbiA9IGFjdGlvbjtcbiAgfVxuXG4gIGlmICghcXVlcnkpIHtcbiAgICBpZiAodGhpcy5jb25maWcuYWxsb3dDdXN0b21PYmplY3RJZCkge1xuICAgICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChkYXRhLCAnb2JqZWN0SWQnKSAmJiAhZGF0YS5vYmplY3RJZCkge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgUGFyc2UuRXJyb3IuTUlTU0lOR19PQkpFQ1RfSUQsXG4gICAgICAgICAgJ29iamVjdElkIG11c3Qgbm90IGJlIGVtcHR5LCBudWxsIG9yIHVuZGVmaW5lZCdcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgaWYgKGRhdGEub2JqZWN0SWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfS0VZX05BTUUsICdvYmplY3RJZCBpcyBhbiBpbnZhbGlkIGZpZWxkIG5hbWUuJyk7XG4gICAgICB9XG4gICAgICBpZiAoZGF0YS5pZCkge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9LRVlfTkFNRSwgJ2lkIGlzIGFuIGludmFsaWQgZmllbGQgbmFtZS4nKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvLyBXaGVuIHRoZSBvcGVyYXRpb24gaXMgY29tcGxldGUsIHRoaXMucmVzcG9uc2UgbWF5IGhhdmUgc2V2ZXJhbFxuICAvLyBmaWVsZHMuXG4gIC8vIHJlc3BvbnNlOiB0aGUgYWN0dWFsIGRhdGEgdG8gYmUgcmV0dXJuZWRcbiAgLy8gc3RhdHVzOiB0aGUgaHR0cCBzdGF0dXMgY29kZS4gaWYgbm90IHByZXNlbnQsIHRyZWF0ZWQgbGlrZSBhIDIwMFxuICAvLyBsb2NhdGlvbjogdGhlIGxvY2F0aW9uIGhlYWRlci4gaWYgbm90IHByZXNlbnQsIG5vIGxvY2F0aW9uIGhlYWRlclxuICB0aGlzLnJlc3BvbnNlID0gbnVsbDtcblxuICAvLyBQcm9jZXNzaW5nIHRoaXMgb3BlcmF0aW9uIG1heSBtdXRhdGUgb3VyIGRhdGEsIHNvIHdlIG9wZXJhdGUgb24gYVxuICAvLyBjb3B5XG4gIHRoaXMucXVlcnkgPSBkZWVwY29weShxdWVyeSk7XG4gIHRoaXMuZGF0YSA9IGRlZXBjb3B5KGRhdGEpO1xuICAvLyBXZSBuZXZlciBjaGFuZ2Ugb3JpZ2luYWxEYXRhLCBzbyB3ZSBkbyBub3QgbmVlZCBhIGRlZXAgY29weVxuICB0aGlzLm9yaWdpbmFsRGF0YSA9IG9yaWdpbmFsRGF0YTtcblxuICAvLyBUaGUgdGltZXN0YW1wIHdlJ2xsIHVzZSBmb3IgdGhpcyB3aG9sZSBvcGVyYXRpb25cbiAgdGhpcy51cGRhdGVkQXQgPSBQYXJzZS5fZW5jb2RlKG5ldyBEYXRlKCkpLmlzbztcblxuICAvLyBTaGFyZWQgU2NoZW1hQ29udHJvbGxlciB0byBiZSByZXVzZWQgdG8gcmVkdWNlIHRoZSBudW1iZXIgb2YgbG9hZFNjaGVtYSgpIGNhbGxzIHBlciByZXF1ZXN0XG4gIC8vIE9uY2Ugc2V0IHRoZSBzY2hlbWFEYXRhIHNob3VsZCBiZSBpbW11dGFibGVcbiAgdGhpcy52YWxpZFNjaGVtYUNvbnRyb2xsZXIgPSBudWxsO1xufVxuXG4vLyBBIGNvbnZlbmllbnQgbWV0aG9kIHRvIHBlcmZvcm0gYWxsIHRoZSBzdGVwcyBvZiBwcm9jZXNzaW5nIHRoZVxuLy8gd3JpdGUsIGluIG9yZGVyLlxuLy8gUmV0dXJucyBhIHByb21pc2UgZm9yIGEge3Jlc3BvbnNlLCBzdGF0dXMsIGxvY2F0aW9ufSBvYmplY3QuXG4vLyBzdGF0dXMgYW5kIGxvY2F0aW9uIGFyZSBvcHRpb25hbC5cblJlc3RXcml0ZS5wcm90b3R5cGUuZXhlY3V0ZSA9IGZ1bmN0aW9uICgpIHtcbiAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpXG4gICAgLnRoZW4oKCkgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMuZ2V0VXNlckFuZFJvbGVBQ0woKTtcbiAgICB9KVxuICAgIC50aGVuKCgpID0+IHtcbiAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlQ2xpZW50Q2xhc3NDcmVhdGlvbigpO1xuICAgIH0pXG4gICAgLnRoZW4oKCkgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMuaGFuZGxlSW5zdGFsbGF0aW9uKCk7XG4gICAgfSlcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy5oYW5kbGVTZXNzaW9uKCk7XG4gICAgfSlcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZUF1dGhEYXRhKCk7XG4gICAgfSlcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy5ydW5CZWZvcmVTYXZlVHJpZ2dlcigpO1xuICAgIH0pXG4gICAgLnRoZW4oKCkgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMuZGVsZXRlRW1haWxSZXNldFRva2VuSWZOZWVkZWQoKTtcbiAgICB9KVxuICAgIC50aGVuKCgpID0+IHtcbiAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlU2NoZW1hKCk7XG4gICAgfSlcbiAgICAudGhlbihzY2hlbWFDb250cm9sbGVyID0+IHtcbiAgICAgIHRoaXMudmFsaWRTY2hlbWFDb250cm9sbGVyID0gc2NoZW1hQ29udHJvbGxlcjtcbiAgICAgIHJldHVybiB0aGlzLnNldFJlcXVpcmVkRmllbGRzSWZOZWVkZWQoKTtcbiAgICB9KVxuICAgIC50aGVuKCgpID0+IHtcbiAgICAgIHJldHVybiB0aGlzLnRyYW5zZm9ybVVzZXIoKTtcbiAgICB9KVxuICAgIC50aGVuKCgpID0+IHtcbiAgICAgIHJldHVybiB0aGlzLmV4cGFuZEZpbGVzRm9yRXhpc3RpbmdPYmplY3RzKCk7XG4gICAgfSlcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy5kZXN0cm95RHVwbGljYXRlZFNlc3Npb25zKCk7XG4gICAgfSlcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy5ydW5EYXRhYmFzZU9wZXJhdGlvbigpO1xuICAgIH0pXG4gICAgLnRoZW4oKCkgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlU2Vzc2lvblRva2VuSWZOZWVkZWQoKTtcbiAgICB9KVxuICAgIC50aGVuKCgpID0+IHtcbiAgICAgIHJldHVybiB0aGlzLmhhbmRsZUZvbGxvd3VwKCk7XG4gICAgfSlcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy5ydW5BZnRlclNhdmVUcmlnZ2VyKCk7XG4gICAgfSlcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy5jbGVhblVzZXJBdXRoRGF0YSgpO1xuICAgIH0pXG4gICAgLnRoZW4oKCkgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMucmVzcG9uc2U7XG4gICAgfSk7XG59O1xuXG4vLyBVc2VzIHRoZSBBdXRoIG9iamVjdCB0byBnZXQgdGhlIGxpc3Qgb2Ygcm9sZXMsIGFkZHMgdGhlIHVzZXIgaWRcblJlc3RXcml0ZS5wcm90b3R5cGUuZ2V0VXNlckFuZFJvbGVBQ0wgPSBmdW5jdGlvbiAoKSB7XG4gIGlmICh0aGlzLmF1dGguaXNNYXN0ZXIpIHtcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gIH1cblxuICB0aGlzLnJ1bk9wdGlvbnMuYWNsID0gWycqJ107XG5cbiAgaWYgKHRoaXMuYXV0aC51c2VyKSB7XG4gICAgcmV0dXJuIHRoaXMuYXV0aC5nZXRVc2VyUm9sZXMoKS50aGVuKHJvbGVzID0+IHtcbiAgICAgIHRoaXMucnVuT3B0aW9ucy5hY2wgPSB0aGlzLnJ1bk9wdGlvbnMuYWNsLmNvbmNhdChyb2xlcywgW3RoaXMuYXV0aC51c2VyLmlkXSk7XG4gICAgICByZXR1cm47XG4gICAgfSk7XG4gIH0gZWxzZSB7XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICB9XG59O1xuXG4vLyBWYWxpZGF0ZXMgdGhpcyBvcGVyYXRpb24gYWdhaW5zdCB0aGUgYWxsb3dDbGllbnRDbGFzc0NyZWF0aW9uIGNvbmZpZy5cblJlc3RXcml0ZS5wcm90b3R5cGUudmFsaWRhdGVDbGllbnRDbGFzc0NyZWF0aW9uID0gZnVuY3Rpb24gKCkge1xuICBpZiAoXG4gICAgdGhpcy5jb25maWcuYWxsb3dDbGllbnRDbGFzc0NyZWF0aW9uID09PSBmYWxzZSAmJlxuICAgICF0aGlzLmF1dGguaXNNYXN0ZXIgJiZcbiAgICBTY2hlbWFDb250cm9sbGVyLnN5c3RlbUNsYXNzZXMuaW5kZXhPZih0aGlzLmNsYXNzTmFtZSkgPT09IC0xXG4gICkge1xuICAgIHJldHVybiB0aGlzLmNvbmZpZy5kYXRhYmFzZVxuICAgICAgLmxvYWRTY2hlbWEoKVxuICAgICAgLnRoZW4oc2NoZW1hQ29udHJvbGxlciA9PiBzY2hlbWFDb250cm9sbGVyLmhhc0NsYXNzKHRoaXMuY2xhc3NOYW1lKSlcbiAgICAgIC50aGVuKGhhc0NsYXNzID0+IHtcbiAgICAgICAgaWYgKGhhc0NsYXNzICE9PSB0cnVlKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuT1BFUkFUSU9OX0ZPUkJJRERFTixcbiAgICAgICAgICAgICdUaGlzIHVzZXIgaXMgbm90IGFsbG93ZWQgdG8gYWNjZXNzICcgKyAnbm9uLWV4aXN0ZW50IGNsYXNzOiAnICsgdGhpcy5jbGFzc05hbWVcbiAgICAgICAgICApO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgfSBlbHNlIHtcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gIH1cbn07XG5cbi8vIFZhbGlkYXRlcyB0aGlzIG9wZXJhdGlvbiBhZ2FpbnN0IHRoZSBzY2hlbWEuXG5SZXN0V3JpdGUucHJvdG90eXBlLnZhbGlkYXRlU2NoZW1hID0gZnVuY3Rpb24gKCkge1xuICByZXR1cm4gdGhpcy5jb25maWcuZGF0YWJhc2UudmFsaWRhdGVPYmplY3QoXG4gICAgdGhpcy5jbGFzc05hbWUsXG4gICAgdGhpcy5kYXRhLFxuICAgIHRoaXMucXVlcnksXG4gICAgdGhpcy5ydW5PcHRpb25zXG4gICk7XG59O1xuXG4vLyBSdW5zIGFueSBiZWZvcmVTYXZlIHRyaWdnZXJzIGFnYWluc3QgdGhpcyBvcGVyYXRpb24uXG4vLyBBbnkgY2hhbmdlIGxlYWRzIHRvIG91ciBkYXRhIGJlaW5nIG11dGF0ZWQuXG5SZXN0V3JpdGUucHJvdG90eXBlLnJ1bkJlZm9yZVNhdmVUcmlnZ2VyID0gZnVuY3Rpb24gKCkge1xuICBpZiAodGhpcy5yZXNwb25zZSkge1xuICAgIHJldHVybjtcbiAgfVxuXG4gIC8vIEF2b2lkIGRvaW5nIGFueSBzZXR1cCBmb3IgdHJpZ2dlcnMgaWYgdGhlcmUgaXMgbm8gJ2JlZm9yZVNhdmUnIHRyaWdnZXIgZm9yIHRoaXMgY2xhc3MuXG4gIGlmIChcbiAgICAhdHJpZ2dlcnMudHJpZ2dlckV4aXN0cyh0aGlzLmNsYXNzTmFtZSwgdHJpZ2dlcnMuVHlwZXMuYmVmb3JlU2F2ZSwgdGhpcy5jb25maWcuYXBwbGljYXRpb25JZClcbiAgKSB7XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICB9XG5cbiAgLy8gQ2xvdWQgY29kZSBnZXRzIGEgYml0IG9mIGV4dHJhIGRhdGEgZm9yIGl0cyBvYmplY3RzXG4gIHZhciBleHRyYURhdGEgPSB7IGNsYXNzTmFtZTogdGhpcy5jbGFzc05hbWUgfTtcbiAgaWYgKHRoaXMucXVlcnkgJiYgdGhpcy5xdWVyeS5vYmplY3RJZCkge1xuICAgIGV4dHJhRGF0YS5vYmplY3RJZCA9IHRoaXMucXVlcnkub2JqZWN0SWQ7XG4gIH1cblxuICBsZXQgb3JpZ2luYWxPYmplY3QgPSBudWxsO1xuICBjb25zdCB1cGRhdGVkT2JqZWN0ID0gdGhpcy5idWlsZFVwZGF0ZWRPYmplY3QoZXh0cmFEYXRhKTtcbiAgaWYgKHRoaXMucXVlcnkgJiYgdGhpcy5xdWVyeS5vYmplY3RJZCkge1xuICAgIC8vIFRoaXMgaXMgYW4gdXBkYXRlIGZvciBleGlzdGluZyBvYmplY3QuXG4gICAgb3JpZ2luYWxPYmplY3QgPSB0cmlnZ2Vycy5pbmZsYXRlKGV4dHJhRGF0YSwgdGhpcy5vcmlnaW5hbERhdGEpO1xuICB9XG5cbiAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpXG4gICAgLnRoZW4oKCkgPT4ge1xuICAgICAgLy8gQmVmb3JlIGNhbGxpbmcgdGhlIHRyaWdnZXIsIHZhbGlkYXRlIHRoZSBwZXJtaXNzaW9ucyBmb3IgdGhlIHNhdmUgb3BlcmF0aW9uXG4gICAgICBsZXQgZGF0YWJhc2VQcm9taXNlID0gbnVsbDtcbiAgICAgIGlmICh0aGlzLnF1ZXJ5KSB7XG4gICAgICAgIC8vIFZhbGlkYXRlIGZvciB1cGRhdGluZ1xuICAgICAgICBkYXRhYmFzZVByb21pc2UgPSB0aGlzLmNvbmZpZy5kYXRhYmFzZS51cGRhdGUoXG4gICAgICAgICAgdGhpcy5jbGFzc05hbWUsXG4gICAgICAgICAgdGhpcy5xdWVyeSxcbiAgICAgICAgICB0aGlzLmRhdGEsXG4gICAgICAgICAgdGhpcy5ydW5PcHRpb25zLFxuICAgICAgICAgIHRydWUsXG4gICAgICAgICAgdHJ1ZVxuICAgICAgICApO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gVmFsaWRhdGUgZm9yIGNyZWF0aW5nXG4gICAgICAgIGRhdGFiYXNlUHJvbWlzZSA9IHRoaXMuY29uZmlnLmRhdGFiYXNlLmNyZWF0ZShcbiAgICAgICAgICB0aGlzLmNsYXNzTmFtZSxcbiAgICAgICAgICB0aGlzLmRhdGEsXG4gICAgICAgICAgdGhpcy5ydW5PcHRpb25zLFxuICAgICAgICAgIHRydWVcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIC8vIEluIHRoZSBjYXNlIHRoYXQgdGhlcmUgaXMgbm8gcGVybWlzc2lvbiBmb3IgdGhlIG9wZXJhdGlvbiwgaXQgdGhyb3dzIGFuIGVycm9yXG4gICAgICByZXR1cm4gZGF0YWJhc2VQcm9taXNlLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgICAgaWYgKCFyZXN1bHQgfHwgcmVzdWx0Lmxlbmd0aCA8PSAwKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLk9CSkVDVF9OT1RfRk9VTkQsICdPYmplY3Qgbm90IGZvdW5kLicpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9KVxuICAgIC50aGVuKCgpID0+IHtcbiAgICAgIHJldHVybiB0cmlnZ2Vycy5tYXliZVJ1blRyaWdnZXIoXG4gICAgICAgIHRyaWdnZXJzLlR5cGVzLmJlZm9yZVNhdmUsXG4gICAgICAgIHRoaXMuYXV0aCxcbiAgICAgICAgdXBkYXRlZE9iamVjdCxcbiAgICAgICAgb3JpZ2luYWxPYmplY3QsXG4gICAgICAgIHRoaXMuY29uZmlnLFxuICAgICAgICB0aGlzLmNvbnRleHRcbiAgICAgICk7XG4gICAgfSlcbiAgICAudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICBpZiAocmVzcG9uc2UgJiYgcmVzcG9uc2Uub2JqZWN0KSB7XG4gICAgICAgIHRoaXMuc3RvcmFnZS5maWVsZHNDaGFuZ2VkQnlUcmlnZ2VyID0gXy5yZWR1Y2UoXG4gICAgICAgICAgcmVzcG9uc2Uub2JqZWN0LFxuICAgICAgICAgIChyZXN1bHQsIHZhbHVlLCBrZXkpID0+IHtcbiAgICAgICAgICAgIGlmICghXy5pc0VxdWFsKHRoaXMuZGF0YVtrZXldLCB2YWx1ZSkpIHtcbiAgICAgICAgICAgICAgcmVzdWx0LnB1c2goa2V5KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICAgICAgfSxcbiAgICAgICAgICBbXVxuICAgICAgICApO1xuICAgICAgICB0aGlzLmRhdGEgPSByZXNwb25zZS5vYmplY3Q7XG4gICAgICAgIC8vIFdlIHNob3VsZCBkZWxldGUgdGhlIG9iamVjdElkIGZvciBhbiB1cGRhdGUgd3JpdGVcbiAgICAgICAgaWYgKHRoaXMucXVlcnkgJiYgdGhpcy5xdWVyeS5vYmplY3RJZCkge1xuICAgICAgICAgIGRlbGV0ZSB0aGlzLmRhdGEub2JqZWN0SWQ7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbn07XG5cblJlc3RXcml0ZS5wcm90b3R5cGUucnVuQmVmb3JlTG9naW5UcmlnZ2VyID0gYXN5bmMgZnVuY3Rpb24gKHVzZXJEYXRhKSB7XG4gIC8vIEF2b2lkIGRvaW5nIGFueSBzZXR1cCBmb3IgdHJpZ2dlcnMgaWYgdGhlcmUgaXMgbm8gJ2JlZm9yZUxvZ2luJyB0cmlnZ2VyXG4gIGlmIChcbiAgICAhdHJpZ2dlcnMudHJpZ2dlckV4aXN0cyh0aGlzLmNsYXNzTmFtZSwgdHJpZ2dlcnMuVHlwZXMuYmVmb3JlTG9naW4sIHRoaXMuY29uZmlnLmFwcGxpY2F0aW9uSWQpXG4gICkge1xuICAgIHJldHVybjtcbiAgfVxuXG4gIC8vIENsb3VkIGNvZGUgZ2V0cyBhIGJpdCBvZiBleHRyYSBkYXRhIGZvciBpdHMgb2JqZWN0c1xuICBjb25zdCBleHRyYURhdGEgPSB7IGNsYXNzTmFtZTogdGhpcy5jbGFzc05hbWUgfTtcblxuICAvLyBFeHBhbmQgZmlsZSBvYmplY3RzXG4gIHRoaXMuY29uZmlnLmZpbGVzQ29udHJvbGxlci5leHBhbmRGaWxlc0luT2JqZWN0KHRoaXMuY29uZmlnLCB1c2VyRGF0YSk7XG5cbiAgY29uc3QgdXNlciA9IHRyaWdnZXJzLmluZmxhdGUoZXh0cmFEYXRhLCB1c2VyRGF0YSk7XG5cbiAgLy8gbm8gbmVlZCB0byByZXR1cm4gYSByZXNwb25zZVxuICBhd2FpdCB0cmlnZ2Vycy5tYXliZVJ1blRyaWdnZXIoXG4gICAgdHJpZ2dlcnMuVHlwZXMuYmVmb3JlTG9naW4sXG4gICAgdGhpcy5hdXRoLFxuICAgIHVzZXIsXG4gICAgbnVsbCxcbiAgICB0aGlzLmNvbmZpZyxcbiAgICB0aGlzLmNvbnRleHRcbiAgKTtcbn07XG5cblJlc3RXcml0ZS5wcm90b3R5cGUuc2V0UmVxdWlyZWRGaWVsZHNJZk5lZWRlZCA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKHRoaXMuZGF0YSkge1xuICAgIHJldHVybiB0aGlzLnZhbGlkU2NoZW1hQ29udHJvbGxlci5nZXRBbGxDbGFzc2VzKCkudGhlbihhbGxDbGFzc2VzID0+IHtcbiAgICAgIGNvbnN0IHNjaGVtYSA9IGFsbENsYXNzZXMuZmluZChvbmVDbGFzcyA9PiBvbmVDbGFzcy5jbGFzc05hbWUgPT09IHRoaXMuY2xhc3NOYW1lKTtcbiAgICAgIGNvbnN0IHNldFJlcXVpcmVkRmllbGRJZk5lZWRlZCA9IChmaWVsZE5hbWUsIHNldERlZmF1bHQpID0+IHtcbiAgICAgICAgaWYgKFxuICAgICAgICAgIHRoaXMuZGF0YVtmaWVsZE5hbWVdID09PSB1bmRlZmluZWQgfHxcbiAgICAgICAgICB0aGlzLmRhdGFbZmllbGROYW1lXSA9PT0gbnVsbCB8fFxuICAgICAgICAgIHRoaXMuZGF0YVtmaWVsZE5hbWVdID09PSAnJyB8fFxuICAgICAgICAgICh0eXBlb2YgdGhpcy5kYXRhW2ZpZWxkTmFtZV0gPT09ICdvYmplY3QnICYmIHRoaXMuZGF0YVtmaWVsZE5hbWVdLl9fb3AgPT09ICdEZWxldGUnKVxuICAgICAgICApIHtcbiAgICAgICAgICBpZiAoXG4gICAgICAgICAgICBzZXREZWZhdWx0ICYmXG4gICAgICAgICAgICBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0gJiZcbiAgICAgICAgICAgIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS5kZWZhdWx0VmFsdWUgIT09IG51bGwgJiZcbiAgICAgICAgICAgIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS5kZWZhdWx0VmFsdWUgIT09IHVuZGVmaW5lZCAmJlxuICAgICAgICAgICAgKHRoaXMuZGF0YVtmaWVsZE5hbWVdID09PSB1bmRlZmluZWQgfHxcbiAgICAgICAgICAgICAgKHR5cGVvZiB0aGlzLmRhdGFbZmllbGROYW1lXSA9PT0gJ29iamVjdCcgJiYgdGhpcy5kYXRhW2ZpZWxkTmFtZV0uX19vcCA9PT0gJ0RlbGV0ZScpKVxuICAgICAgICAgICkge1xuICAgICAgICAgICAgdGhpcy5kYXRhW2ZpZWxkTmFtZV0gPSBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0uZGVmYXVsdFZhbHVlO1xuICAgICAgICAgICAgdGhpcy5zdG9yYWdlLmZpZWxkc0NoYW5nZWRCeVRyaWdnZXIgPSB0aGlzLnN0b3JhZ2UuZmllbGRzQ2hhbmdlZEJ5VHJpZ2dlciB8fCBbXTtcbiAgICAgICAgICAgIGlmICh0aGlzLnN0b3JhZ2UuZmllbGRzQ2hhbmdlZEJ5VHJpZ2dlci5pbmRleE9mKGZpZWxkTmFtZSkgPCAwKSB7XG4gICAgICAgICAgICAgIHRoaXMuc3RvcmFnZS5maWVsZHNDaGFuZ2VkQnlUcmlnZ2VyLnB1c2goZmllbGROYW1lKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9IGVsc2UgaWYgKHNjaGVtYS5maWVsZHNbZmllbGROYW1lXSAmJiBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0ucmVxdWlyZWQgPT09IHRydWUpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5WQUxJREFUSU9OX0VSUk9SLCBgJHtmaWVsZE5hbWV9IGlzIHJlcXVpcmVkYCk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9O1xuXG4gICAgICAvLyBBZGQgZGVmYXVsdCBmaWVsZHNcbiAgICAgIHRoaXMuZGF0YS51cGRhdGVkQXQgPSB0aGlzLnVwZGF0ZWRBdDtcbiAgICAgIGlmICghdGhpcy5xdWVyeSkge1xuICAgICAgICB0aGlzLmRhdGEuY3JlYXRlZEF0ID0gdGhpcy51cGRhdGVkQXQ7XG5cbiAgICAgICAgLy8gT25seSBhc3NpZ24gbmV3IG9iamVjdElkIGlmIHdlIGFyZSBjcmVhdGluZyBuZXcgb2JqZWN0XG4gICAgICAgIGlmICghdGhpcy5kYXRhLm9iamVjdElkKSB7XG4gICAgICAgICAgdGhpcy5kYXRhLm9iamVjdElkID0gY3J5cHRvVXRpbHMubmV3T2JqZWN0SWQodGhpcy5jb25maWcub2JqZWN0SWRTaXplKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoc2NoZW1hKSB7XG4gICAgICAgICAgT2JqZWN0LmtleXMoc2NoZW1hLmZpZWxkcykuZm9yRWFjaChmaWVsZE5hbWUgPT4ge1xuICAgICAgICAgICAgc2V0UmVxdWlyZWRGaWVsZElmTmVlZGVkKGZpZWxkTmFtZSwgdHJ1ZSk7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSBpZiAoc2NoZW1hKSB7XG4gICAgICAgIE9iamVjdC5rZXlzKHRoaXMuZGF0YSkuZm9yRWFjaChmaWVsZE5hbWUgPT4ge1xuICAgICAgICAgIHNldFJlcXVpcmVkRmllbGRJZk5lZWRlZChmaWVsZE5hbWUsIGZhbHNlKTtcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbiAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xufTtcblxuLy8gVHJhbnNmb3JtcyBhdXRoIGRhdGEgZm9yIGEgdXNlciBvYmplY3QuXG4vLyBEb2VzIG5vdGhpbmcgaWYgdGhpcyBpc24ndCBhIHVzZXIgb2JqZWN0LlxuLy8gUmV0dXJucyBhIHByb21pc2UgZm9yIHdoZW4gd2UncmUgZG9uZSBpZiBpdCBjYW4ndCBmaW5pc2ggdGhpcyB0aWNrLlxuUmVzdFdyaXRlLnByb3RvdHlwZS52YWxpZGF0ZUF1dGhEYXRhID0gZnVuY3Rpb24gKCkge1xuICBpZiAodGhpcy5jbGFzc05hbWUgIT09ICdfVXNlcicpIHtcbiAgICByZXR1cm47XG4gIH1cblxuICBpZiAoIXRoaXMucXVlcnkgJiYgIXRoaXMuZGF0YS5hdXRoRGF0YSkge1xuICAgIGlmICh0eXBlb2YgdGhpcy5kYXRhLnVzZXJuYW1lICE9PSAnc3RyaW5nJyB8fCBfLmlzRW1wdHkodGhpcy5kYXRhLnVzZXJuYW1lKSkge1xuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLlVTRVJOQU1FX01JU1NJTkcsICdiYWQgb3IgbWlzc2luZyB1c2VybmFtZScpO1xuICAgIH1cbiAgICBpZiAodHlwZW9mIHRoaXMuZGF0YS5wYXNzd29yZCAhPT0gJ3N0cmluZycgfHwgXy5pc0VtcHR5KHRoaXMuZGF0YS5wYXNzd29yZCkpIHtcbiAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5QQVNTV09SRF9NSVNTSU5HLCAncGFzc3dvcmQgaXMgcmVxdWlyZWQnKTtcbiAgICB9XG4gIH1cblxuICBpZiAoXG4gICAgKHRoaXMuZGF0YS5hdXRoRGF0YSAmJiAhT2JqZWN0LmtleXModGhpcy5kYXRhLmF1dGhEYXRhKS5sZW5ndGgpIHx8XG4gICAgIU9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbCh0aGlzLmRhdGEsICdhdXRoRGF0YScpXG4gICkge1xuICAgIC8vIEhhbmRsZSBzYXZpbmcgYXV0aERhdGEgdG8ge30gb3IgaWYgYXV0aERhdGEgZG9lc24ndCBleGlzdFxuICAgIHJldHVybjtcbiAgfSBlbHNlIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwodGhpcy5kYXRhLCAnYXV0aERhdGEnKSAmJiAhdGhpcy5kYXRhLmF1dGhEYXRhKSB7XG4gICAgLy8gSGFuZGxlIHNhdmluZyBhdXRoRGF0YSB0byBudWxsXG4gICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgUGFyc2UuRXJyb3IuVU5TVVBQT1JURURfU0VSVklDRSxcbiAgICAgICdUaGlzIGF1dGhlbnRpY2F0aW9uIG1ldGhvZCBpcyB1bnN1cHBvcnRlZC4nXG4gICAgKTtcbiAgfVxuXG4gIHZhciBhdXRoRGF0YSA9IHRoaXMuZGF0YS5hdXRoRGF0YTtcbiAgdmFyIHByb3ZpZGVycyA9IE9iamVjdC5rZXlzKGF1dGhEYXRhKTtcbiAgaWYgKHByb3ZpZGVycy5sZW5ndGggPiAwKSB7XG4gICAgY29uc3QgY2FuSGFuZGxlQXV0aERhdGEgPSBwcm92aWRlcnMucmVkdWNlKChjYW5IYW5kbGUsIHByb3ZpZGVyKSA9PiB7XG4gICAgICB2YXIgcHJvdmlkZXJBdXRoRGF0YSA9IGF1dGhEYXRhW3Byb3ZpZGVyXTtcbiAgICAgIHZhciBoYXNUb2tlbiA9IHByb3ZpZGVyQXV0aERhdGEgJiYgcHJvdmlkZXJBdXRoRGF0YS5pZDtcbiAgICAgIHJldHVybiBjYW5IYW5kbGUgJiYgKGhhc1Rva2VuIHx8IHByb3ZpZGVyQXV0aERhdGEgPT0gbnVsbCk7XG4gICAgfSwgdHJ1ZSk7XG4gICAgaWYgKGNhbkhhbmRsZUF1dGhEYXRhKSB7XG4gICAgICByZXR1cm4gdGhpcy5oYW5kbGVBdXRoRGF0YShhdXRoRGF0YSk7XG4gICAgfVxuICB9XG4gIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICBQYXJzZS5FcnJvci5VTlNVUFBPUlRFRF9TRVJWSUNFLFxuICAgICdUaGlzIGF1dGhlbnRpY2F0aW9uIG1ldGhvZCBpcyB1bnN1cHBvcnRlZC4nXG4gICk7XG59O1xuXG5SZXN0V3JpdGUucHJvdG90eXBlLmhhbmRsZUF1dGhEYXRhVmFsaWRhdGlvbiA9IGZ1bmN0aW9uIChhdXRoRGF0YSkge1xuICBjb25zdCB2YWxpZGF0aW9ucyA9IE9iamVjdC5rZXlzKGF1dGhEYXRhKS5tYXAocHJvdmlkZXIgPT4ge1xuICAgIGlmIChhdXRoRGF0YVtwcm92aWRlcl0gPT09IG51bGwpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICB9XG4gICAgY29uc3QgdmFsaWRhdGVBdXRoRGF0YSA9IHRoaXMuY29uZmlnLmF1dGhEYXRhTWFuYWdlci5nZXRWYWxpZGF0b3JGb3JQcm92aWRlcihwcm92aWRlcik7XG4gICAgaWYgKCF2YWxpZGF0ZUF1dGhEYXRhKSB7XG4gICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgIFBhcnNlLkVycm9yLlVOU1VQUE9SVEVEX1NFUlZJQ0UsXG4gICAgICAgICdUaGlzIGF1dGhlbnRpY2F0aW9uIG1ldGhvZCBpcyB1bnN1cHBvcnRlZC4nXG4gICAgICApO1xuICAgIH1cbiAgICByZXR1cm4gdmFsaWRhdGVBdXRoRGF0YShhdXRoRGF0YVtwcm92aWRlcl0pO1xuICB9KTtcbiAgcmV0dXJuIFByb21pc2UuYWxsKHZhbGlkYXRpb25zKTtcbn07XG5cblJlc3RXcml0ZS5wcm90b3R5cGUuZmluZFVzZXJzV2l0aEF1dGhEYXRhID0gZnVuY3Rpb24gKGF1dGhEYXRhKSB7XG4gIGNvbnN0IHByb3ZpZGVycyA9IE9iamVjdC5rZXlzKGF1dGhEYXRhKTtcbiAgY29uc3QgcXVlcnkgPSBwcm92aWRlcnNcbiAgICAucmVkdWNlKChtZW1vLCBwcm92aWRlcikgPT4ge1xuICAgICAgaWYgKCFhdXRoRGF0YVtwcm92aWRlcl0pIHtcbiAgICAgICAgcmV0dXJuIG1lbW87XG4gICAgICB9XG4gICAgICBjb25zdCBxdWVyeUtleSA9IGBhdXRoRGF0YS4ke3Byb3ZpZGVyfS5pZGA7XG4gICAgICBjb25zdCBxdWVyeSA9IHt9O1xuICAgICAgcXVlcnlbcXVlcnlLZXldID0gYXV0aERhdGFbcHJvdmlkZXJdLmlkO1xuICAgICAgbWVtby5wdXNoKHF1ZXJ5KTtcbiAgICAgIHJldHVybiBtZW1vO1xuICAgIH0sIFtdKVxuICAgIC5maWx0ZXIocSA9PiB7XG4gICAgICByZXR1cm4gdHlwZW9mIHEgIT09ICd1bmRlZmluZWQnO1xuICAgIH0pO1xuXG4gIGxldCBmaW5kUHJvbWlzZSA9IFByb21pc2UucmVzb2x2ZShbXSk7XG4gIGlmIChxdWVyeS5sZW5ndGggPiAwKSB7XG4gICAgZmluZFByb21pc2UgPSB0aGlzLmNvbmZpZy5kYXRhYmFzZS5maW5kKHRoaXMuY2xhc3NOYW1lLCB7ICRvcjogcXVlcnkgfSwge30pO1xuICB9XG5cbiAgcmV0dXJuIGZpbmRQcm9taXNlO1xufTtcblxuUmVzdFdyaXRlLnByb3RvdHlwZS5maWx0ZXJlZE9iamVjdHNCeUFDTCA9IGZ1bmN0aW9uIChvYmplY3RzKSB7XG4gIGlmICh0aGlzLmF1dGguaXNNYXN0ZXIpIHtcbiAgICByZXR1cm4gb2JqZWN0cztcbiAgfVxuICByZXR1cm4gb2JqZWN0cy5maWx0ZXIob2JqZWN0ID0+IHtcbiAgICBpZiAoIW9iamVjdC5BQ0wpIHtcbiAgICAgIHJldHVybiB0cnVlOyAvLyBsZWdhY3kgdXNlcnMgdGhhdCBoYXZlIG5vIEFDTCBmaWVsZCBvbiB0aGVtXG4gICAgfVxuICAgIC8vIFJlZ3VsYXIgdXNlcnMgdGhhdCBoYXZlIGJlZW4gbG9ja2VkIG91dC5cbiAgICByZXR1cm4gb2JqZWN0LkFDTCAmJiBPYmplY3Qua2V5cyhvYmplY3QuQUNMKS5sZW5ndGggPiAwO1xuICB9KTtcbn07XG5cblJlc3RXcml0ZS5wcm90b3R5cGUuaGFuZGxlQXV0aERhdGEgPSBmdW5jdGlvbiAoYXV0aERhdGEpIHtcbiAgbGV0IHJlc3VsdHM7XG4gIHJldHVybiB0aGlzLmZpbmRVc2Vyc1dpdGhBdXRoRGF0YShhdXRoRGF0YSkudGhlbihhc3luYyByID0+IHtcbiAgICByZXN1bHRzID0gdGhpcy5maWx0ZXJlZE9iamVjdHNCeUFDTChyKTtcblxuICAgIGlmIChyZXN1bHRzLmxlbmd0aCA9PSAxKSB7XG4gICAgICB0aGlzLnN0b3JhZ2VbJ2F1dGhQcm92aWRlciddID0gT2JqZWN0LmtleXMoYXV0aERhdGEpLmpvaW4oJywnKTtcblxuICAgICAgY29uc3QgdXNlclJlc3VsdCA9IHJlc3VsdHNbMF07XG4gICAgICBjb25zdCBtdXRhdGVkQXV0aERhdGEgPSB7fTtcbiAgICAgIE9iamVjdC5rZXlzKGF1dGhEYXRhKS5mb3JFYWNoKHByb3ZpZGVyID0+IHtcbiAgICAgICAgY29uc3QgcHJvdmlkZXJEYXRhID0gYXV0aERhdGFbcHJvdmlkZXJdO1xuICAgICAgICBjb25zdCB1c2VyQXV0aERhdGEgPSB1c2VyUmVzdWx0LmF1dGhEYXRhW3Byb3ZpZGVyXTtcbiAgICAgICAgaWYgKCFfLmlzRXF1YWwocHJvdmlkZXJEYXRhLCB1c2VyQXV0aERhdGEpKSB7XG4gICAgICAgICAgbXV0YXRlZEF1dGhEYXRhW3Byb3ZpZGVyXSA9IHByb3ZpZGVyRGF0YTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgICBjb25zdCBoYXNNdXRhdGVkQXV0aERhdGEgPSBPYmplY3Qua2V5cyhtdXRhdGVkQXV0aERhdGEpLmxlbmd0aCAhPT0gMDtcbiAgICAgIGxldCB1c2VySWQ7XG4gICAgICBpZiAodGhpcy5xdWVyeSAmJiB0aGlzLnF1ZXJ5Lm9iamVjdElkKSB7XG4gICAgICAgIHVzZXJJZCA9IHRoaXMucXVlcnkub2JqZWN0SWQ7XG4gICAgICB9IGVsc2UgaWYgKHRoaXMuYXV0aCAmJiB0aGlzLmF1dGgudXNlciAmJiB0aGlzLmF1dGgudXNlci5pZCkge1xuICAgICAgICB1c2VySWQgPSB0aGlzLmF1dGgudXNlci5pZDtcbiAgICAgIH1cbiAgICAgIGlmICghdXNlcklkIHx8IHVzZXJJZCA9PT0gdXNlclJlc3VsdC5vYmplY3RJZCkge1xuICAgICAgICAvLyBubyB1c2VyIG1ha2luZyB0aGUgY2FsbFxuICAgICAgICAvLyBPUiB0aGUgdXNlciBtYWtpbmcgdGhlIGNhbGwgaXMgdGhlIHJpZ2h0IG9uZVxuICAgICAgICAvLyBMb2dpbiB3aXRoIGF1dGggZGF0YVxuICAgICAgICBkZWxldGUgcmVzdWx0c1swXS5wYXNzd29yZDtcblxuICAgICAgICAvLyBuZWVkIHRvIHNldCB0aGUgb2JqZWN0SWQgZmlyc3Qgb3RoZXJ3aXNlIGxvY2F0aW9uIGhhcyB0cmFpbGluZyB1bmRlZmluZWRcbiAgICAgICAgdGhpcy5kYXRhLm9iamVjdElkID0gdXNlclJlc3VsdC5vYmplY3RJZDtcblxuICAgICAgICBpZiAoIXRoaXMucXVlcnkgfHwgIXRoaXMucXVlcnkub2JqZWN0SWQpIHtcbiAgICAgICAgICAvLyB0aGlzIGEgbG9naW4gY2FsbCwgbm8gdXNlcklkIHBhc3NlZFxuICAgICAgICAgIHRoaXMucmVzcG9uc2UgPSB7XG4gICAgICAgICAgICByZXNwb25zZTogdXNlclJlc3VsdCxcbiAgICAgICAgICAgIGxvY2F0aW9uOiB0aGlzLmxvY2F0aW9uKCksXG4gICAgICAgICAgfTtcbiAgICAgICAgICAvLyBSdW4gYmVmb3JlTG9naW4gaG9vayBiZWZvcmUgc3RvcmluZyBhbnkgdXBkYXRlc1xuICAgICAgICAgIC8vIHRvIGF1dGhEYXRhIG9uIHRoZSBkYjsgY2hhbmdlcyB0byB1c2VyUmVzdWx0XG4gICAgICAgICAgLy8gd2lsbCBiZSBpZ25vcmVkLlxuICAgICAgICAgIGF3YWl0IHRoaXMucnVuQmVmb3JlTG9naW5UcmlnZ2VyKGRlZXBjb3B5KHVzZXJSZXN1bHQpKTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIElmIHdlIGRpZG4ndCBjaGFuZ2UgdGhlIGF1dGggZGF0YSwganVzdCBrZWVwIGdvaW5nXG4gICAgICAgIGlmICghaGFzTXV0YXRlZEF1dGhEYXRhKSB7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICAgIC8vIFdlIGhhdmUgYXV0aERhdGEgdGhhdCBpcyB1cGRhdGVkIG9uIGxvZ2luXG4gICAgICAgIC8vIHRoYXQgY2FuIGhhcHBlbiB3aGVuIHRva2VuIGFyZSByZWZyZXNoZWQsXG4gICAgICAgIC8vIFdlIHNob3VsZCB1cGRhdGUgdGhlIHRva2VuIGFuZCBsZXQgdGhlIHVzZXIgaW5cbiAgICAgICAgLy8gV2Ugc2hvdWxkIG9ubHkgY2hlY2sgdGhlIG11dGF0ZWQga2V5c1xuICAgICAgICByZXR1cm4gdGhpcy5oYW5kbGVBdXRoRGF0YVZhbGlkYXRpb24obXV0YXRlZEF1dGhEYXRhKS50aGVuKGFzeW5jICgpID0+IHtcbiAgICAgICAgICAvLyBJRiB3ZSBoYXZlIGEgcmVzcG9uc2UsIHdlJ2xsIHNraXAgdGhlIGRhdGFiYXNlIG9wZXJhdGlvbiAvIGJlZm9yZVNhdmUgLyBhZnRlclNhdmUgZXRjLi4uXG4gICAgICAgICAgLy8gd2UgbmVlZCB0byBzZXQgaXQgdXAgdGhlcmUuXG4gICAgICAgICAgLy8gV2UgYXJlIHN1cHBvc2VkIHRvIGhhdmUgYSByZXNwb25zZSBvbmx5IG9uIExPR0lOIHdpdGggYXV0aERhdGEsIHNvIHdlIHNraXAgdGhvc2VcbiAgICAgICAgICAvLyBJZiB3ZSdyZSBub3QgbG9nZ2luZyBpbiwgYnV0IGp1c3QgdXBkYXRpbmcgdGhlIGN1cnJlbnQgdXNlciwgd2UgY2FuIHNhZmVseSBza2lwIHRoYXQgcGFydFxuICAgICAgICAgIGlmICh0aGlzLnJlc3BvbnNlKSB7XG4gICAgICAgICAgICAvLyBBc3NpZ24gdGhlIG5ldyBhdXRoRGF0YSBpbiB0aGUgcmVzcG9uc2VcbiAgICAgICAgICAgIE9iamVjdC5rZXlzKG11dGF0ZWRBdXRoRGF0YSkuZm9yRWFjaChwcm92aWRlciA9PiB7XG4gICAgICAgICAgICAgIHRoaXMucmVzcG9uc2UucmVzcG9uc2UuYXV0aERhdGFbcHJvdmlkZXJdID0gbXV0YXRlZEF1dGhEYXRhW3Byb3ZpZGVyXTtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICAvLyBSdW4gdGhlIERCIHVwZGF0ZSBkaXJlY3RseSwgYXMgJ21hc3RlcidcbiAgICAgICAgICAgIC8vIEp1c3QgdXBkYXRlIHRoZSBhdXRoRGF0YSBwYXJ0XG4gICAgICAgICAgICAvLyBUaGVuIHdlJ3JlIGdvb2QgZm9yIHRoZSB1c2VyLCBlYXJseSBleGl0IG9mIHNvcnRzXG4gICAgICAgICAgICByZXR1cm4gdGhpcy5jb25maWcuZGF0YWJhc2UudXBkYXRlKFxuICAgICAgICAgICAgICB0aGlzLmNsYXNzTmFtZSxcbiAgICAgICAgICAgICAgeyBvYmplY3RJZDogdGhpcy5kYXRhLm9iamVjdElkIH0sXG4gICAgICAgICAgICAgIHsgYXV0aERhdGE6IG11dGF0ZWRBdXRoRGF0YSB9LFxuICAgICAgICAgICAgICB7fVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBlbHNlIGlmICh1c2VySWQpIHtcbiAgICAgICAgLy8gVHJ5aW5nIHRvIHVwZGF0ZSBhdXRoIGRhdGEgYnV0IHVzZXJzXG4gICAgICAgIC8vIGFyZSBkaWZmZXJlbnRcbiAgICAgICAgaWYgKHVzZXJSZXN1bHQub2JqZWN0SWQgIT09IHVzZXJJZCkge1xuICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5BQ0NPVU5UX0FMUkVBRFlfTElOS0VELCAndGhpcyBhdXRoIGlzIGFscmVhZHkgdXNlZCcpO1xuICAgICAgICB9XG4gICAgICAgIC8vIE5vIGF1dGggZGF0YSB3YXMgbXV0YXRlZCwganVzdCBrZWVwIGdvaW5nXG4gICAgICAgIGlmICghaGFzTXV0YXRlZEF1dGhEYXRhKSB7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiB0aGlzLmhhbmRsZUF1dGhEYXRhVmFsaWRhdGlvbihhdXRoRGF0YSkudGhlbigoKSA9PiB7XG4gICAgICBpZiAocmVzdWx0cy5sZW5ndGggPiAxKSB7XG4gICAgICAgIC8vIE1vcmUgdGhhbiAxIHVzZXIgd2l0aCB0aGUgcGFzc2VkIGlkJ3NcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLkFDQ09VTlRfQUxSRUFEWV9MSU5LRUQsICd0aGlzIGF1dGggaXMgYWxyZWFkeSB1c2VkJyk7XG4gICAgICB9XG4gICAgfSk7XG4gIH0pO1xufTtcblxuLy8gVGhlIG5vbi10aGlyZC1wYXJ0eSBwYXJ0cyBvZiBVc2VyIHRyYW5zZm9ybWF0aW9uXG5SZXN0V3JpdGUucHJvdG90eXBlLnRyYW5zZm9ybVVzZXIgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBwcm9taXNlID0gUHJvbWlzZS5yZXNvbHZlKCk7XG5cbiAgaWYgKHRoaXMuY2xhc3NOYW1lICE9PSAnX1VzZXInKSB7XG4gICAgcmV0dXJuIHByb21pc2U7XG4gIH1cblxuICBpZiAoIXRoaXMuYXV0aC5pc01hc3RlciAmJiAnZW1haWxWZXJpZmllZCcgaW4gdGhpcy5kYXRhKSB7XG4gICAgY29uc3QgZXJyb3IgPSBgQ2xpZW50cyBhcmVuJ3QgYWxsb3dlZCB0byBtYW51YWxseSB1cGRhdGUgZW1haWwgdmVyaWZpY2F0aW9uLmA7XG4gICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLk9QRVJBVElPTl9GT1JCSURERU4sIGVycm9yKTtcbiAgfVxuXG4gIC8vIERvIG5vdCBjbGVhbnVwIHNlc3Npb24gaWYgb2JqZWN0SWQgaXMgbm90IHNldFxuICBpZiAodGhpcy5xdWVyeSAmJiB0aGlzLm9iamVjdElkKCkpIHtcbiAgICAvLyBJZiB3ZSdyZSB1cGRhdGluZyBhIF9Vc2VyIG9iamVjdCwgd2UgbmVlZCB0byBjbGVhciBvdXQgdGhlIGNhY2hlIGZvciB0aGF0IHVzZXIuIEZpbmQgYWxsIHRoZWlyXG4gICAgLy8gc2Vzc2lvbiB0b2tlbnMsIGFuZCByZW1vdmUgdGhlbSBmcm9tIHRoZSBjYWNoZS5cbiAgICBwcm9taXNlID0gbmV3IFJlc3RRdWVyeSh0aGlzLmNvbmZpZywgQXV0aC5tYXN0ZXIodGhpcy5jb25maWcpLCAnX1Nlc3Npb24nLCB7XG4gICAgICB1c2VyOiB7XG4gICAgICAgIF9fdHlwZTogJ1BvaW50ZXInLFxuICAgICAgICBjbGFzc05hbWU6ICdfVXNlcicsXG4gICAgICAgIG9iamVjdElkOiB0aGlzLm9iamVjdElkKCksXG4gICAgICB9LFxuICAgIH0pXG4gICAgICAuZXhlY3V0ZSgpXG4gICAgICAudGhlbihyZXN1bHRzID0+IHtcbiAgICAgICAgcmVzdWx0cy5yZXN1bHRzLmZvckVhY2goc2Vzc2lvbiA9PlxuICAgICAgICAgIHRoaXMuY29uZmlnLmNhY2hlQ29udHJvbGxlci51c2VyLmRlbChzZXNzaW9uLnNlc3Npb25Ub2tlbilcbiAgICAgICAgKTtcbiAgICAgIH0pO1xuICB9XG5cbiAgcmV0dXJuIHByb21pc2VcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICAvLyBUcmFuc2Zvcm0gdGhlIHBhc3N3b3JkXG4gICAgICBpZiAodGhpcy5kYXRhLnBhc3N3b3JkID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgLy8gaWdub3JlIG9ubHkgaWYgdW5kZWZpbmVkLiBzaG91bGQgcHJvY2VlZCBpZiBlbXB0eSAoJycpXG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKHRoaXMucXVlcnkpIHtcbiAgICAgICAgdGhpcy5zdG9yYWdlWydjbGVhclNlc3Npb25zJ10gPSB0cnVlO1xuICAgICAgICAvLyBHZW5lcmF0ZSBhIG5ldyBzZXNzaW9uIG9ubHkgaWYgdGhlIHVzZXIgcmVxdWVzdGVkXG4gICAgICAgIGlmICghdGhpcy5hdXRoLmlzTWFzdGVyKSB7XG4gICAgICAgICAgdGhpcy5zdG9yYWdlWydnZW5lcmF0ZU5ld1Nlc3Npb24nXSA9IHRydWU7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHRoaXMuX3ZhbGlkYXRlUGFzc3dvcmRQb2xpY3koKS50aGVuKCgpID0+IHtcbiAgICAgICAgcmV0dXJuIHBhc3N3b3JkQ3J5cHRvLmhhc2godGhpcy5kYXRhLnBhc3N3b3JkKS50aGVuKGhhc2hlZFBhc3N3b3JkID0+IHtcbiAgICAgICAgICB0aGlzLmRhdGEuX2hhc2hlZF9wYXNzd29yZCA9IGhhc2hlZFBhc3N3b3JkO1xuICAgICAgICAgIGRlbGV0ZSB0aGlzLmRhdGEucGFzc3dvcmQ7XG4gICAgICAgIH0pO1xuICAgICAgfSk7XG4gICAgfSlcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy5fdmFsaWRhdGVVc2VyTmFtZSgpO1xuICAgIH0pXG4gICAgLnRoZW4oKCkgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMuX3ZhbGlkYXRlRW1haWwoKTtcbiAgICB9KTtcbn07XG5cblJlc3RXcml0ZS5wcm90b3R5cGUuX3ZhbGlkYXRlVXNlck5hbWUgPSBmdW5jdGlvbiAoKSB7XG4gIC8vIENoZWNrIGZvciB1c2VybmFtZSB1bmlxdWVuZXNzXG4gIGlmICghdGhpcy5kYXRhLnVzZXJuYW1lKSB7XG4gICAgaWYgKCF0aGlzLnF1ZXJ5KSB7XG4gICAgICB0aGlzLmRhdGEudXNlcm5hbWUgPSBjcnlwdG9VdGlscy5yYW5kb21TdHJpbmcoMjUpO1xuICAgICAgdGhpcy5yZXNwb25zZVNob3VsZEhhdmVVc2VybmFtZSA9IHRydWU7XG4gICAgfVxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgfVxuICAvKlxuICAgIFVzZXJuYW1lcyBzaG91bGQgYmUgdW5pcXVlIHdoZW4gY29tcGFyZWQgY2FzZSBpbnNlbnNpdGl2ZWx5XG5cbiAgICBVc2VycyBzaG91bGQgYmUgYWJsZSB0byBtYWtlIGNhc2Ugc2Vuc2l0aXZlIHVzZXJuYW1lcyBhbmRcbiAgICBsb2dpbiB1c2luZyB0aGUgY2FzZSB0aGV5IGVudGVyZWQuICBJLmUuICdTbm9vcHknIHNob3VsZCBwcmVjbHVkZVxuICAgICdzbm9vcHknIGFzIGEgdmFsaWQgdXNlcm5hbWUuXG4gICovXG4gIHJldHVybiB0aGlzLmNvbmZpZy5kYXRhYmFzZVxuICAgIC5maW5kKFxuICAgICAgdGhpcy5jbGFzc05hbWUsXG4gICAgICB7XG4gICAgICAgIHVzZXJuYW1lOiB0aGlzLmRhdGEudXNlcm5hbWUsXG4gICAgICAgIG9iamVjdElkOiB7ICRuZTogdGhpcy5vYmplY3RJZCgpIH0sXG4gICAgICB9LFxuICAgICAgeyBsaW1pdDogMSwgY2FzZUluc2Vuc2l0aXZlOiB0cnVlIH0sXG4gICAgICB7fSxcbiAgICAgIHRoaXMudmFsaWRTY2hlbWFDb250cm9sbGVyXG4gICAgKVxuICAgIC50aGVuKHJlc3VsdHMgPT4ge1xuICAgICAgaWYgKHJlc3VsdHMubGVuZ3RoID4gMCkge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgUGFyc2UuRXJyb3IuVVNFUk5BTUVfVEFLRU4sXG4gICAgICAgICAgJ0FjY291bnQgYWxyZWFkeSBleGlzdHMgZm9yIHRoaXMgdXNlcm5hbWUuJ1xuICAgICAgICApO1xuICAgICAgfVxuICAgICAgcmV0dXJuO1xuICAgIH0pO1xufTtcblxuLypcbiAgQXMgd2l0aCB1c2VybmFtZXMsIFBhcnNlIHNob3VsZCBub3QgYWxsb3cgY2FzZSBpbnNlbnNpdGl2ZSBjb2xsaXNpb25zIG9mIGVtYWlsLlxuICB1bmxpa2Ugd2l0aCB1c2VybmFtZXMgKHdoaWNoIGNhbiBoYXZlIGNhc2UgaW5zZW5zaXRpdmUgY29sbGlzaW9ucyBpbiB0aGUgY2FzZSBvZlxuICBhdXRoIGFkYXB0ZXJzKSwgZW1haWxzIHNob3VsZCBuZXZlciBoYXZlIGEgY2FzZSBpbnNlbnNpdGl2ZSBjb2xsaXNpb24uXG5cbiAgVGhpcyBiZWhhdmlvciBjYW4gYmUgZW5mb3JjZWQgdGhyb3VnaCBhIHByb3Blcmx5IGNvbmZpZ3VyZWQgaW5kZXggc2VlOlxuICBodHRwczovL2RvY3MubW9uZ29kYi5jb20vbWFudWFsL2NvcmUvaW5kZXgtY2FzZS1pbnNlbnNpdGl2ZS8jY3JlYXRlLWEtY2FzZS1pbnNlbnNpdGl2ZS1pbmRleFxuICB3aGljaCBjb3VsZCBiZSBpbXBsZW1lbnRlZCBpbnN0ZWFkIG9mIHRoaXMgY29kZSBiYXNlZCB2YWxpZGF0aW9uLlxuXG4gIEdpdmVuIHRoYXQgdGhpcyBsb29rdXAgc2hvdWxkIGJlIGEgcmVsYXRpdmVseSBsb3cgdXNlIGNhc2UgYW5kIHRoYXQgdGhlIGNhc2Ugc2Vuc2l0aXZlXG4gIHVuaXF1ZSBpbmRleCB3aWxsIGJlIHVzZWQgYnkgdGhlIGRiIGZvciB0aGUgcXVlcnksIHRoaXMgaXMgYW4gYWRlcXVhdGUgc29sdXRpb24uXG4qL1xuUmVzdFdyaXRlLnByb3RvdHlwZS5fdmFsaWRhdGVFbWFpbCA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKCF0aGlzLmRhdGEuZW1haWwgfHwgdGhpcy5kYXRhLmVtYWlsLl9fb3AgPT09ICdEZWxldGUnKSB7XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICB9XG4gIC8vIFZhbGlkYXRlIGJhc2ljIGVtYWlsIGFkZHJlc3MgZm9ybWF0XG4gIGlmICghdGhpcy5kYXRhLmVtYWlsLm1hdGNoKC9eLitALiskLykpIHtcbiAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoXG4gICAgICBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9FTUFJTF9BRERSRVNTLCAnRW1haWwgYWRkcmVzcyBmb3JtYXQgaXMgaW52YWxpZC4nKVxuICAgICk7XG4gIH1cbiAgLy8gQ2FzZSBpbnNlbnNpdGl2ZSBtYXRjaCwgc2VlIG5vdGUgYWJvdmUgZnVuY3Rpb24uXG4gIHJldHVybiB0aGlzLmNvbmZpZy5kYXRhYmFzZVxuICAgIC5maW5kKFxuICAgICAgdGhpcy5jbGFzc05hbWUsXG4gICAgICB7XG4gICAgICAgIGVtYWlsOiB0aGlzLmRhdGEuZW1haWwsXG4gICAgICAgIG9iamVjdElkOiB7ICRuZTogdGhpcy5vYmplY3RJZCgpIH0sXG4gICAgICB9LFxuICAgICAgeyBsaW1pdDogMSwgY2FzZUluc2Vuc2l0aXZlOiB0cnVlIH0sXG4gICAgICB7fSxcbiAgICAgIHRoaXMudmFsaWRTY2hlbWFDb250cm9sbGVyXG4gICAgKVxuICAgIC50aGVuKHJlc3VsdHMgPT4ge1xuICAgICAgaWYgKHJlc3VsdHMubGVuZ3RoID4gMCkge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgUGFyc2UuRXJyb3IuRU1BSUxfVEFLRU4sXG4gICAgICAgICAgJ0FjY291bnQgYWxyZWFkeSBleGlzdHMgZm9yIHRoaXMgZW1haWwgYWRkcmVzcy4nXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgICBpZiAoXG4gICAgICAgICF0aGlzLmRhdGEuYXV0aERhdGEgfHxcbiAgICAgICAgIU9iamVjdC5rZXlzKHRoaXMuZGF0YS5hdXRoRGF0YSkubGVuZ3RoIHx8XG4gICAgICAgIChPYmplY3Qua2V5cyh0aGlzLmRhdGEuYXV0aERhdGEpLmxlbmd0aCA9PT0gMSAmJlxuICAgICAgICAgIE9iamVjdC5rZXlzKHRoaXMuZGF0YS5hdXRoRGF0YSlbMF0gPT09ICdhbm9ueW1vdXMnKVxuICAgICAgKSB7XG4gICAgICAgIC8vIFdlIHVwZGF0ZWQgdGhlIGVtYWlsLCBzZW5kIGEgbmV3IHZhbGlkYXRpb25cbiAgICAgICAgdGhpcy5zdG9yYWdlWydzZW5kVmVyaWZpY2F0aW9uRW1haWwnXSA9IHRydWU7XG4gICAgICAgIHRoaXMuY29uZmlnLnVzZXJDb250cm9sbGVyLnNldEVtYWlsVmVyaWZ5VG9rZW4odGhpcy5kYXRhKTtcbiAgICAgIH1cbiAgICB9KTtcbn07XG5cblJlc3RXcml0ZS5wcm90b3R5cGUuX3ZhbGlkYXRlUGFzc3dvcmRQb2xpY3kgPSBmdW5jdGlvbiAoKSB7XG4gIGlmICghdGhpcy5jb25maWcucGFzc3dvcmRQb2xpY3kpIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgcmV0dXJuIHRoaXMuX3ZhbGlkYXRlUGFzc3dvcmRSZXF1aXJlbWVudHMoKS50aGVuKCgpID0+IHtcbiAgICByZXR1cm4gdGhpcy5fdmFsaWRhdGVQYXNzd29yZEhpc3RvcnkoKTtcbiAgfSk7XG59O1xuXG5SZXN0V3JpdGUucHJvdG90eXBlLl92YWxpZGF0ZVBhc3N3b3JkUmVxdWlyZW1lbnRzID0gZnVuY3Rpb24gKCkge1xuICAvLyBjaGVjayBpZiB0aGUgcGFzc3dvcmQgY29uZm9ybXMgdG8gdGhlIGRlZmluZWQgcGFzc3dvcmQgcG9saWN5IGlmIGNvbmZpZ3VyZWRcbiAgLy8gSWYgd2Ugc3BlY2lmaWVkIGEgY3VzdG9tIGVycm9yIGluIG91ciBjb25maWd1cmF0aW9uIHVzZSBpdC5cbiAgLy8gRXhhbXBsZTogXCJQYXNzd29yZHMgbXVzdCBpbmNsdWRlIGEgQ2FwaXRhbCBMZXR0ZXIsIExvd2VyY2FzZSBMZXR0ZXIsIGFuZCBhIG51bWJlci5cIlxuICAvL1xuICAvLyBUaGlzIGlzIGVzcGVjaWFsbHkgdXNlZnVsIG9uIHRoZSBnZW5lcmljIFwicGFzc3dvcmQgcmVzZXRcIiBwYWdlLFxuICAvLyBhcyBpdCBhbGxvd3MgdGhlIHByb2dyYW1tZXIgdG8gY29tbXVuaWNhdGUgc3BlY2lmaWMgcmVxdWlyZW1lbnRzIGluc3RlYWQgb2Y6XG4gIC8vIGEuIG1ha2luZyB0aGUgdXNlciBndWVzcyB3aGF0cyB3cm9uZ1xuICAvLyBiLiBtYWtpbmcgYSBjdXN0b20gcGFzc3dvcmQgcmVzZXQgcGFnZSB0aGF0IHNob3dzIHRoZSByZXF1aXJlbWVudHNcbiAgY29uc3QgcG9saWN5RXJyb3IgPSB0aGlzLmNvbmZpZy5wYXNzd29yZFBvbGljeS52YWxpZGF0aW9uRXJyb3JcbiAgICA/IHRoaXMuY29uZmlnLnBhc3N3b3JkUG9saWN5LnZhbGlkYXRpb25FcnJvclxuICAgIDogJ1Bhc3N3b3JkIGRvZXMgbm90IG1lZXQgdGhlIFBhc3N3b3JkIFBvbGljeSByZXF1aXJlbWVudHMuJztcbiAgY29uc3QgY29udGFpbnNVc2VybmFtZUVycm9yID0gJ1Bhc3N3b3JkIGNhbm5vdCBjb250YWluIHlvdXIgdXNlcm5hbWUuJztcblxuICAvLyBjaGVjayB3aGV0aGVyIHRoZSBwYXNzd29yZCBtZWV0cyB0aGUgcGFzc3dvcmQgc3RyZW5ndGggcmVxdWlyZW1lbnRzXG4gIGlmIChcbiAgICAodGhpcy5jb25maWcucGFzc3dvcmRQb2xpY3kucGF0dGVyblZhbGlkYXRvciAmJlxuICAgICAgIXRoaXMuY29uZmlnLnBhc3N3b3JkUG9saWN5LnBhdHRlcm5WYWxpZGF0b3IodGhpcy5kYXRhLnBhc3N3b3JkKSkgfHxcbiAgICAodGhpcy5jb25maWcucGFzc3dvcmRQb2xpY3kudmFsaWRhdG9yQ2FsbGJhY2sgJiZcbiAgICAgICF0aGlzLmNvbmZpZy5wYXNzd29yZFBvbGljeS52YWxpZGF0b3JDYWxsYmFjayh0aGlzLmRhdGEucGFzc3dvcmQpKVxuICApIHtcbiAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLlZBTElEQVRJT05fRVJST1IsIHBvbGljeUVycm9yKSk7XG4gIH1cblxuICAvLyBjaGVjayB3aGV0aGVyIHBhc3N3b3JkIGNvbnRhaW4gdXNlcm5hbWVcbiAgaWYgKHRoaXMuY29uZmlnLnBhc3N3b3JkUG9saWN5LmRvTm90QWxsb3dVc2VybmFtZSA9PT0gdHJ1ZSkge1xuICAgIGlmICh0aGlzLmRhdGEudXNlcm5hbWUpIHtcbiAgICAgIC8vIHVzZXJuYW1lIGlzIG5vdCBwYXNzZWQgZHVyaW5nIHBhc3N3b3JkIHJlc2V0XG4gICAgICBpZiAodGhpcy5kYXRhLnBhc3N3b3JkLmluZGV4T2YodGhpcy5kYXRhLnVzZXJuYW1lKSA+PSAwKVxuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QobmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLlZBTElEQVRJT05fRVJST1IsIGNvbnRhaW5zVXNlcm5hbWVFcnJvcikpO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyByZXRyaWV2ZSB0aGUgVXNlciBvYmplY3QgdXNpbmcgb2JqZWN0SWQgZHVyaW5nIHBhc3N3b3JkIHJlc2V0XG4gICAgICByZXR1cm4gdGhpcy5jb25maWcuZGF0YWJhc2UuZmluZCgnX1VzZXInLCB7IG9iamVjdElkOiB0aGlzLm9iamVjdElkKCkgfSkudGhlbihyZXN1bHRzID0+IHtcbiAgICAgICAgaWYgKHJlc3VsdHMubGVuZ3RoICE9IDEpIHtcbiAgICAgICAgICB0aHJvdyB1bmRlZmluZWQ7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHRoaXMuZGF0YS5wYXNzd29yZC5pbmRleE9mKHJlc3VsdHNbMF0udXNlcm5hbWUpID49IDApXG4gICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KFxuICAgICAgICAgICAgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLlZBTElEQVRJT05fRVJST1IsIGNvbnRhaW5zVXNlcm5hbWVFcnJvcilcbiAgICAgICAgICApO1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICB9KTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xufTtcblxuUmVzdFdyaXRlLnByb3RvdHlwZS5fdmFsaWRhdGVQYXNzd29yZEhpc3RvcnkgPSBmdW5jdGlvbiAoKSB7XG4gIC8vIGNoZWNrIHdoZXRoZXIgcGFzc3dvcmQgaXMgcmVwZWF0aW5nIGZyb20gc3BlY2lmaWVkIGhpc3RvcnlcbiAgaWYgKHRoaXMucXVlcnkgJiYgdGhpcy5jb25maWcucGFzc3dvcmRQb2xpY3kubWF4UGFzc3dvcmRIaXN0b3J5KSB7XG4gICAgcmV0dXJuIHRoaXMuY29uZmlnLmRhdGFiYXNlXG4gICAgICAuZmluZChcbiAgICAgICAgJ19Vc2VyJyxcbiAgICAgICAgeyBvYmplY3RJZDogdGhpcy5vYmplY3RJZCgpIH0sXG4gICAgICAgIHsga2V5czogWydfcGFzc3dvcmRfaGlzdG9yeScsICdfaGFzaGVkX3Bhc3N3b3JkJ10gfVxuICAgICAgKVxuICAgICAgLnRoZW4ocmVzdWx0cyA9PiB7XG4gICAgICAgIGlmIChyZXN1bHRzLmxlbmd0aCAhPSAxKSB7XG4gICAgICAgICAgdGhyb3cgdW5kZWZpbmVkO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHVzZXIgPSByZXN1bHRzWzBdO1xuICAgICAgICBsZXQgb2xkUGFzc3dvcmRzID0gW107XG4gICAgICAgIGlmICh1c2VyLl9wYXNzd29yZF9oaXN0b3J5KVxuICAgICAgICAgIG9sZFBhc3N3b3JkcyA9IF8udGFrZShcbiAgICAgICAgICAgIHVzZXIuX3Bhc3N3b3JkX2hpc3RvcnksXG4gICAgICAgICAgICB0aGlzLmNvbmZpZy5wYXNzd29yZFBvbGljeS5tYXhQYXNzd29yZEhpc3RvcnkgLSAxXG4gICAgICAgICAgKTtcbiAgICAgICAgb2xkUGFzc3dvcmRzLnB1c2godXNlci5wYXNzd29yZCk7XG4gICAgICAgIGNvbnN0IG5ld1Bhc3N3b3JkID0gdGhpcy5kYXRhLnBhc3N3b3JkO1xuICAgICAgICAvLyBjb21wYXJlIHRoZSBuZXcgcGFzc3dvcmQgaGFzaCB3aXRoIGFsbCBvbGQgcGFzc3dvcmQgaGFzaGVzXG4gICAgICAgIGNvbnN0IHByb21pc2VzID0gb2xkUGFzc3dvcmRzLm1hcChmdW5jdGlvbiAoaGFzaCkge1xuICAgICAgICAgIHJldHVybiBwYXNzd29yZENyeXB0by5jb21wYXJlKG5ld1Bhc3N3b3JkLCBoYXNoKS50aGVuKHJlc3VsdCA9PiB7XG4gICAgICAgICAgICBpZiAocmVzdWx0KVxuICAgICAgICAgICAgICAvLyByZWplY3QgaWYgdGhlcmUgaXMgYSBtYXRjaFxuICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoJ1JFUEVBVF9QQVNTV09SRCcpO1xuICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgICAgICAgIH0pO1xuICAgICAgICB9KTtcbiAgICAgICAgLy8gd2FpdCBmb3IgYWxsIGNvbXBhcmlzb25zIHRvIGNvbXBsZXRlXG4gICAgICAgIHJldHVybiBQcm9taXNlLmFsbChwcm9taXNlcylcbiAgICAgICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgICAgfSlcbiAgICAgICAgICAuY2F0Y2goZXJyID0+IHtcbiAgICAgICAgICAgIGlmIChlcnIgPT09ICdSRVBFQVRfUEFTU1dPUkQnKVxuICAgICAgICAgICAgICAvLyBhIG1hdGNoIHdhcyBmb3VuZFxuICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoXG4gICAgICAgICAgICAgICAgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICAgICAgUGFyc2UuRXJyb3IuVkFMSURBVElPTl9FUlJPUixcbiAgICAgICAgICAgICAgICAgIGBOZXcgcGFzc3dvcmQgc2hvdWxkIG5vdCBiZSB0aGUgc2FtZSBhcyBsYXN0ICR7dGhpcy5jb25maWcucGFzc3dvcmRQb2xpY3kubWF4UGFzc3dvcmRIaXN0b3J5fSBwYXNzd29yZHMuYFxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIHRocm93IGVycjtcbiAgICAgICAgICB9KTtcbiAgICAgIH0pO1xuICB9XG4gIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbn07XG5cblJlc3RXcml0ZS5wcm90b3R5cGUuY3JlYXRlU2Vzc2lvblRva2VuSWZOZWVkZWQgPSBmdW5jdGlvbiAoKSB7XG4gIGlmICh0aGlzLmNsYXNzTmFtZSAhPT0gJ19Vc2VyJykge1xuICAgIHJldHVybjtcbiAgfVxuICAvLyBEb24ndCBnZW5lcmF0ZSBzZXNzaW9uIGZvciB1cGRhdGluZyB1c2VyICh0aGlzLnF1ZXJ5IGlzIHNldCkgdW5sZXNzIGF1dGhEYXRhIGV4aXN0c1xuICBpZiAodGhpcy5xdWVyeSAmJiAhdGhpcy5kYXRhLmF1dGhEYXRhKSB7XG4gICAgcmV0dXJuO1xuICB9XG4gIC8vIERvbid0IGdlbmVyYXRlIG5ldyBzZXNzaW9uVG9rZW4gaWYgbGlua2luZyB2aWEgc2Vzc2lvblRva2VuXG4gIGlmICh0aGlzLmF1dGgudXNlciAmJiB0aGlzLmRhdGEuYXV0aERhdGEpIHtcbiAgICByZXR1cm47XG4gIH1cbiAgaWYgKFxuICAgICF0aGlzLnN0b3JhZ2VbJ2F1dGhQcm92aWRlciddICYmIC8vIHNpZ251cCBjYWxsLCB3aXRoXG4gICAgdGhpcy5jb25maWcucHJldmVudExvZ2luV2l0aFVudmVyaWZpZWRFbWFpbCAmJiAvLyBubyBsb2dpbiB3aXRob3V0IHZlcmlmaWNhdGlvblxuICAgIHRoaXMuY29uZmlnLnZlcmlmeVVzZXJFbWFpbHNcbiAgKSB7XG4gICAgLy8gdmVyaWZpY2F0aW9uIGlzIG9uXG4gICAgcmV0dXJuOyAvLyBkbyBub3QgY3JlYXRlIHRoZSBzZXNzaW9uIHRva2VuIGluIHRoYXQgY2FzZSFcbiAgfVxuICByZXR1cm4gdGhpcy5jcmVhdGVTZXNzaW9uVG9rZW4oKTtcbn07XG5cblJlc3RXcml0ZS5wcm90b3R5cGUuY3JlYXRlU2Vzc2lvblRva2VuID0gYXN5bmMgZnVuY3Rpb24gKCkge1xuICAvLyBjbG91ZCBpbnN0YWxsYXRpb25JZCBmcm9tIENsb3VkIENvZGUsXG4gIC8vIG5ldmVyIGNyZWF0ZSBzZXNzaW9uIHRva2VucyBmcm9tIHRoZXJlLlxuICBpZiAodGhpcy5hdXRoLmluc3RhbGxhdGlvbklkICYmIHRoaXMuYXV0aC5pbnN0YWxsYXRpb25JZCA9PT0gJ2Nsb3VkJykge1xuICAgIHJldHVybjtcbiAgfVxuXG4gIGNvbnN0IHsgc2Vzc2lvbkRhdGEsIGNyZWF0ZVNlc3Npb24gfSA9IFJlc3RXcml0ZS5jcmVhdGVTZXNzaW9uKHRoaXMuY29uZmlnLCB7XG4gICAgdXNlcklkOiB0aGlzLm9iamVjdElkKCksXG4gICAgY3JlYXRlZFdpdGg6IHtcbiAgICAgIGFjdGlvbjogdGhpcy5zdG9yYWdlWydhdXRoUHJvdmlkZXInXSA/ICdsb2dpbicgOiAnc2lnbnVwJyxcbiAgICAgIGF1dGhQcm92aWRlcjogdGhpcy5zdG9yYWdlWydhdXRoUHJvdmlkZXInXSB8fCAncGFzc3dvcmQnLFxuICAgIH0sXG4gICAgaW5zdGFsbGF0aW9uSWQ6IHRoaXMuYXV0aC5pbnN0YWxsYXRpb25JZCxcbiAgfSk7XG5cbiAgaWYgKHRoaXMucmVzcG9uc2UgJiYgdGhpcy5yZXNwb25zZS5yZXNwb25zZSkge1xuICAgIHRoaXMucmVzcG9uc2UucmVzcG9uc2Uuc2Vzc2lvblRva2VuID0gc2Vzc2lvbkRhdGEuc2Vzc2lvblRva2VuO1xuICB9XG5cbiAgcmV0dXJuIGNyZWF0ZVNlc3Npb24oKTtcbn07XG5cblJlc3RXcml0ZS5jcmVhdGVTZXNzaW9uID0gZnVuY3Rpb24gKFxuICBjb25maWcsXG4gIHsgdXNlcklkLCBjcmVhdGVkV2l0aCwgaW5zdGFsbGF0aW9uSWQsIGFkZGl0aW9uYWxTZXNzaW9uRGF0YSB9XG4pIHtcbiAgY29uc3QgdG9rZW4gPSAncjonICsgY3J5cHRvVXRpbHMubmV3VG9rZW4oKTtcbiAgY29uc3QgZXhwaXJlc0F0ID0gY29uZmlnLmdlbmVyYXRlU2Vzc2lvbkV4cGlyZXNBdCgpO1xuICBjb25zdCBzZXNzaW9uRGF0YSA9IHtcbiAgICBzZXNzaW9uVG9rZW46IHRva2VuLFxuICAgIHVzZXI6IHtcbiAgICAgIF9fdHlwZTogJ1BvaW50ZXInLFxuICAgICAgY2xhc3NOYW1lOiAnX1VzZXInLFxuICAgICAgb2JqZWN0SWQ6IHVzZXJJZCxcbiAgICB9LFxuICAgIGNyZWF0ZWRXaXRoLFxuICAgIHJlc3RyaWN0ZWQ6IGZhbHNlLFxuICAgIGV4cGlyZXNBdDogUGFyc2UuX2VuY29kZShleHBpcmVzQXQpLFxuICB9O1xuXG4gIGlmIChpbnN0YWxsYXRpb25JZCkge1xuICAgIHNlc3Npb25EYXRhLmluc3RhbGxhdGlvbklkID0gaW5zdGFsbGF0aW9uSWQ7XG4gIH1cblxuICBPYmplY3QuYXNzaWduKHNlc3Npb25EYXRhLCBhZGRpdGlvbmFsU2Vzc2lvbkRhdGEpO1xuXG4gIHJldHVybiB7XG4gICAgc2Vzc2lvbkRhdGEsXG4gICAgY3JlYXRlU2Vzc2lvbjogKCkgPT5cbiAgICAgIG5ldyBSZXN0V3JpdGUoY29uZmlnLCBBdXRoLm1hc3Rlcihjb25maWcpLCAnX1Nlc3Npb24nLCBudWxsLCBzZXNzaW9uRGF0YSkuZXhlY3V0ZSgpLFxuICB9O1xufTtcblxuLy8gRGVsZXRlIGVtYWlsIHJlc2V0IHRva2VucyBpZiB1c2VyIGlzIGNoYW5naW5nIHBhc3N3b3JkIG9yIGVtYWlsLlxuUmVzdFdyaXRlLnByb3RvdHlwZS5kZWxldGVFbWFpbFJlc2V0VG9rZW5JZk5lZWRlZCA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKHRoaXMuY2xhc3NOYW1lICE9PSAnX1VzZXInIHx8IHRoaXMucXVlcnkgPT09IG51bGwpIHtcbiAgICAvLyBudWxsIHF1ZXJ5IG1lYW5zIGNyZWF0ZVxuICAgIHJldHVybjtcbiAgfVxuXG4gIGlmICgncGFzc3dvcmQnIGluIHRoaXMuZGF0YSB8fCAnZW1haWwnIGluIHRoaXMuZGF0YSkge1xuICAgIGNvbnN0IGFkZE9wcyA9IHtcbiAgICAgIF9wZXJpc2hhYmxlX3Rva2VuOiB7IF9fb3A6ICdEZWxldGUnIH0sXG4gICAgICBfcGVyaXNoYWJsZV90b2tlbl9leHBpcmVzX2F0OiB7IF9fb3A6ICdEZWxldGUnIH0sXG4gICAgfTtcbiAgICB0aGlzLmRhdGEgPSBPYmplY3QuYXNzaWduKHRoaXMuZGF0YSwgYWRkT3BzKTtcbiAgfVxufTtcblxuUmVzdFdyaXRlLnByb3RvdHlwZS5kZXN0cm95RHVwbGljYXRlZFNlc3Npb25zID0gZnVuY3Rpb24gKCkge1xuICAvLyBPbmx5IGZvciBfU2Vzc2lvbiwgYW5kIGF0IGNyZWF0aW9uIHRpbWVcbiAgaWYgKHRoaXMuY2xhc3NOYW1lICE9ICdfU2Vzc2lvbicgfHwgdGhpcy5xdWVyeSkge1xuICAgIHJldHVybjtcbiAgfVxuICAvLyBEZXN0cm95IHRoZSBzZXNzaW9ucyBpbiAnQmFja2dyb3VuZCdcbiAgY29uc3QgeyB1c2VyLCBpbnN0YWxsYXRpb25JZCwgc2Vzc2lvblRva2VuIH0gPSB0aGlzLmRhdGE7XG4gIGlmICghdXNlciB8fCAhaW5zdGFsbGF0aW9uSWQpIHtcbiAgICByZXR1cm47XG4gIH1cbiAgaWYgKCF1c2VyLm9iamVjdElkKSB7XG4gICAgcmV0dXJuO1xuICB9XG4gIHRoaXMuY29uZmlnLmRhdGFiYXNlLmRlc3Ryb3koXG4gICAgJ19TZXNzaW9uJyxcbiAgICB7XG4gICAgICB1c2VyLFxuICAgICAgaW5zdGFsbGF0aW9uSWQsXG4gICAgICBzZXNzaW9uVG9rZW46IHsgJG5lOiBzZXNzaW9uVG9rZW4gfSxcbiAgICB9LFxuICAgIHt9LFxuICAgIHRoaXMudmFsaWRTY2hlbWFDb250cm9sbGVyXG4gICk7XG59O1xuXG4vLyBIYW5kbGVzIGFueSBmb2xsb3d1cCBsb2dpY1xuUmVzdFdyaXRlLnByb3RvdHlwZS5oYW5kbGVGb2xsb3d1cCA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKHRoaXMuc3RvcmFnZSAmJiB0aGlzLnN0b3JhZ2VbJ2NsZWFyU2Vzc2lvbnMnXSAmJiB0aGlzLmNvbmZpZy5yZXZva2VTZXNzaW9uT25QYXNzd29yZFJlc2V0KSB7XG4gICAgdmFyIHNlc3Npb25RdWVyeSA9IHtcbiAgICAgIHVzZXI6IHtcbiAgICAgICAgX190eXBlOiAnUG9pbnRlcicsXG4gICAgICAgIGNsYXNzTmFtZTogJ19Vc2VyJyxcbiAgICAgICAgb2JqZWN0SWQ6IHRoaXMub2JqZWN0SWQoKSxcbiAgICAgIH0sXG4gICAgfTtcbiAgICBkZWxldGUgdGhpcy5zdG9yYWdlWydjbGVhclNlc3Npb25zJ107XG4gICAgcmV0dXJuIHRoaXMuY29uZmlnLmRhdGFiYXNlXG4gICAgICAuZGVzdHJveSgnX1Nlc3Npb24nLCBzZXNzaW9uUXVlcnkpXG4gICAgICAudGhlbih0aGlzLmhhbmRsZUZvbGxvd3VwLmJpbmQodGhpcykpO1xuICB9XG5cbiAgaWYgKHRoaXMuc3RvcmFnZSAmJiB0aGlzLnN0b3JhZ2VbJ2dlbmVyYXRlTmV3U2Vzc2lvbiddKSB7XG4gICAgZGVsZXRlIHRoaXMuc3RvcmFnZVsnZ2VuZXJhdGVOZXdTZXNzaW9uJ107XG4gICAgcmV0dXJuIHRoaXMuY3JlYXRlU2Vzc2lvblRva2VuKCkudGhlbih0aGlzLmhhbmRsZUZvbGxvd3VwLmJpbmQodGhpcykpO1xuICB9XG5cbiAgaWYgKHRoaXMuc3RvcmFnZSAmJiB0aGlzLnN0b3JhZ2VbJ3NlbmRWZXJpZmljYXRpb25FbWFpbCddKSB7XG4gICAgZGVsZXRlIHRoaXMuc3RvcmFnZVsnc2VuZFZlcmlmaWNhdGlvbkVtYWlsJ107XG4gICAgLy8gRmlyZSBhbmQgZm9yZ2V0IVxuICAgIHRoaXMuY29uZmlnLnVzZXJDb250cm9sbGVyLnNlbmRWZXJpZmljYXRpb25FbWFpbCh0aGlzLmRhdGEpO1xuICAgIHJldHVybiB0aGlzLmhhbmRsZUZvbGxvd3VwLmJpbmQodGhpcyk7XG4gIH1cbn07XG5cbi8vIEhhbmRsZXMgdGhlIF9TZXNzaW9uIGNsYXNzIHNwZWNpYWxuZXNzLlxuLy8gRG9lcyBub3RoaW5nIGlmIHRoaXMgaXNuJ3QgYW4gX1Nlc3Npb24gb2JqZWN0LlxuUmVzdFdyaXRlLnByb3RvdHlwZS5oYW5kbGVTZXNzaW9uID0gZnVuY3Rpb24gKCkge1xuICBpZiAodGhpcy5yZXNwb25zZSB8fCB0aGlzLmNsYXNzTmFtZSAhPT0gJ19TZXNzaW9uJykge1xuICAgIHJldHVybjtcbiAgfVxuXG4gIGlmICghdGhpcy5hdXRoLnVzZXIgJiYgIXRoaXMuYXV0aC5pc01hc3Rlcikge1xuICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX1NFU1NJT05fVE9LRU4sICdTZXNzaW9uIHRva2VuIHJlcXVpcmVkLicpO1xuICB9XG5cbiAgLy8gVE9ETzogVmVyaWZ5IHByb3BlciBlcnJvciB0byB0aHJvd1xuICBpZiAodGhpcy5kYXRhLkFDTCkge1xuICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0tFWV9OQU1FLCAnQ2Fubm90IHNldCAnICsgJ0FDTCBvbiBhIFNlc3Npb24uJyk7XG4gIH1cblxuICBpZiAodGhpcy5xdWVyeSkge1xuICAgIGlmICh0aGlzLmRhdGEudXNlciAmJiAhdGhpcy5hdXRoLmlzTWFzdGVyICYmIHRoaXMuZGF0YS51c2VyLm9iamVjdElkICE9IHRoaXMuYXV0aC51c2VyLmlkKSB7XG4gICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9LRVlfTkFNRSk7XG4gICAgfSBlbHNlIGlmICh0aGlzLmRhdGEuaW5zdGFsbGF0aW9uSWQpIHtcbiAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0tFWV9OQU1FKTtcbiAgICB9IGVsc2UgaWYgKHRoaXMuZGF0YS5zZXNzaW9uVG9rZW4pIHtcbiAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0tFWV9OQU1FKTtcbiAgICB9XG4gIH1cblxuICBpZiAoIXRoaXMucXVlcnkgJiYgIXRoaXMuYXV0aC5pc01hc3Rlcikge1xuICAgIGNvbnN0IGFkZGl0aW9uYWxTZXNzaW9uRGF0YSA9IHt9O1xuICAgIGZvciAodmFyIGtleSBpbiB0aGlzLmRhdGEpIHtcbiAgICAgIGlmIChrZXkgPT09ICdvYmplY3RJZCcgfHwga2V5ID09PSAndXNlcicpIHtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG4gICAgICBhZGRpdGlvbmFsU2Vzc2lvbkRhdGFba2V5XSA9IHRoaXMuZGF0YVtrZXldO1xuICAgIH1cblxuICAgIGNvbnN0IHsgc2Vzc2lvbkRhdGEsIGNyZWF0ZVNlc3Npb24gfSA9IFJlc3RXcml0ZS5jcmVhdGVTZXNzaW9uKHRoaXMuY29uZmlnLCB7XG4gICAgICB1c2VySWQ6IHRoaXMuYXV0aC51c2VyLmlkLFxuICAgICAgY3JlYXRlZFdpdGg6IHtcbiAgICAgICAgYWN0aW9uOiAnY3JlYXRlJyxcbiAgICAgIH0sXG4gICAgICBhZGRpdGlvbmFsU2Vzc2lvbkRhdGEsXG4gICAgfSk7XG5cbiAgICByZXR1cm4gY3JlYXRlU2Vzc2lvbigpLnRoZW4ocmVzdWx0cyA9PiB7XG4gICAgICBpZiAoIXJlc3VsdHMucmVzcG9uc2UpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVEVSTkFMX1NFUlZFUl9FUlJPUiwgJ0Vycm9yIGNyZWF0aW5nIHNlc3Npb24uJyk7XG4gICAgICB9XG4gICAgICBzZXNzaW9uRGF0YVsnb2JqZWN0SWQnXSA9IHJlc3VsdHMucmVzcG9uc2VbJ29iamVjdElkJ107XG4gICAgICB0aGlzLnJlc3BvbnNlID0ge1xuICAgICAgICBzdGF0dXM6IDIwMSxcbiAgICAgICAgbG9jYXRpb246IHJlc3VsdHMubG9jYXRpb24sXG4gICAgICAgIHJlc3BvbnNlOiBzZXNzaW9uRGF0YSxcbiAgICAgIH07XG4gICAgfSk7XG4gIH1cbn07XG5cbi8vIEhhbmRsZXMgdGhlIF9JbnN0YWxsYXRpb24gY2xhc3Mgc3BlY2lhbG5lc3MuXG4vLyBEb2VzIG5vdGhpbmcgaWYgdGhpcyBpc24ndCBhbiBpbnN0YWxsYXRpb24gb2JqZWN0LlxuLy8gSWYgYW4gaW5zdGFsbGF0aW9uIGlzIGZvdW5kLCB0aGlzIGNhbiBtdXRhdGUgdGhpcy5xdWVyeSBhbmQgdHVybiBhIGNyZWF0ZVxuLy8gaW50byBhbiB1cGRhdGUuXG4vLyBSZXR1cm5zIGEgcHJvbWlzZSBmb3Igd2hlbiB3ZSdyZSBkb25lIGlmIGl0IGNhbid0IGZpbmlzaCB0aGlzIHRpY2suXG5SZXN0V3JpdGUucHJvdG90eXBlLmhhbmRsZUluc3RhbGxhdGlvbiA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKHRoaXMucmVzcG9uc2UgfHwgdGhpcy5jbGFzc05hbWUgIT09ICdfSW5zdGFsbGF0aW9uJykge1xuICAgIHJldHVybjtcbiAgfVxuXG4gIGlmIChcbiAgICAhdGhpcy5xdWVyeSAmJlxuICAgICF0aGlzLmRhdGEuZGV2aWNlVG9rZW4gJiZcbiAgICAhdGhpcy5kYXRhLmluc3RhbGxhdGlvbklkICYmXG4gICAgIXRoaXMuYXV0aC5pbnN0YWxsYXRpb25JZFxuICApIHtcbiAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAxMzUsXG4gICAgICAnYXQgbGVhc3Qgb25lIElEIGZpZWxkIChkZXZpY2VUb2tlbiwgaW5zdGFsbGF0aW9uSWQpICcgKyAnbXVzdCBiZSBzcGVjaWZpZWQgaW4gdGhpcyBvcGVyYXRpb24nXG4gICAgKTtcbiAgfVxuXG4gIC8vIElmIHRoZSBkZXZpY2UgdG9rZW4gaXMgNjQgY2hhcmFjdGVycyBsb25nLCB3ZSBhc3N1bWUgaXQgaXMgZm9yIGlPU1xuICAvLyBhbmQgbG93ZXJjYXNlIGl0LlxuICBpZiAodGhpcy5kYXRhLmRldmljZVRva2VuICYmIHRoaXMuZGF0YS5kZXZpY2VUb2tlbi5sZW5ndGggPT0gNjQpIHtcbiAgICB0aGlzLmRhdGEuZGV2aWNlVG9rZW4gPSB0aGlzLmRhdGEuZGV2aWNlVG9rZW4udG9Mb3dlckNhc2UoKTtcbiAgfVxuXG4gIC8vIFdlIGxvd2VyY2FzZSB0aGUgaW5zdGFsbGF0aW9uSWQgaWYgcHJlc2VudFxuICBpZiAodGhpcy5kYXRhLmluc3RhbGxhdGlvbklkKSB7XG4gICAgdGhpcy5kYXRhLmluc3RhbGxhdGlvbklkID0gdGhpcy5kYXRhLmluc3RhbGxhdGlvbklkLnRvTG93ZXJDYXNlKCk7XG4gIH1cblxuICBsZXQgaW5zdGFsbGF0aW9uSWQgPSB0aGlzLmRhdGEuaW5zdGFsbGF0aW9uSWQ7XG5cbiAgLy8gSWYgZGF0YS5pbnN0YWxsYXRpb25JZCBpcyBub3Qgc2V0IGFuZCB3ZSdyZSBub3QgbWFzdGVyLCB3ZSBjYW4gbG9va3VwIGluIGF1dGhcbiAgaWYgKCFpbnN0YWxsYXRpb25JZCAmJiAhdGhpcy5hdXRoLmlzTWFzdGVyKSB7XG4gICAgaW5zdGFsbGF0aW9uSWQgPSB0aGlzLmF1dGguaW5zdGFsbGF0aW9uSWQ7XG4gIH1cblxuICBpZiAoaW5zdGFsbGF0aW9uSWQpIHtcbiAgICBpbnN0YWxsYXRpb25JZCA9IGluc3RhbGxhdGlvbklkLnRvTG93ZXJDYXNlKCk7XG4gIH1cblxuICAvLyBVcGRhdGluZyBfSW5zdGFsbGF0aW9uIGJ1dCBub3QgdXBkYXRpbmcgYW55dGhpbmcgY3JpdGljYWxcbiAgaWYgKHRoaXMucXVlcnkgJiYgIXRoaXMuZGF0YS5kZXZpY2VUb2tlbiAmJiAhaW5zdGFsbGF0aW9uSWQgJiYgIXRoaXMuZGF0YS5kZXZpY2VUeXBlKSB7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgdmFyIHByb21pc2UgPSBQcm9taXNlLnJlc29sdmUoKTtcblxuICB2YXIgaWRNYXRjaDsgLy8gV2lsbCBiZSBhIG1hdGNoIG9uIGVpdGhlciBvYmplY3RJZCBvciBpbnN0YWxsYXRpb25JZFxuICB2YXIgb2JqZWN0SWRNYXRjaDtcbiAgdmFyIGluc3RhbGxhdGlvbklkTWF0Y2g7XG4gIHZhciBkZXZpY2VUb2tlbk1hdGNoZXMgPSBbXTtcblxuICAvLyBJbnN0ZWFkIG9mIGlzc3VpbmcgMyByZWFkcywgbGV0J3MgZG8gaXQgd2l0aCBvbmUgT1IuXG4gIGNvbnN0IG9yUXVlcmllcyA9IFtdO1xuICBpZiAodGhpcy5xdWVyeSAmJiB0aGlzLnF1ZXJ5Lm9iamVjdElkKSB7XG4gICAgb3JRdWVyaWVzLnB1c2goe1xuICAgICAgb2JqZWN0SWQ6IHRoaXMucXVlcnkub2JqZWN0SWQsXG4gICAgfSk7XG4gIH1cbiAgaWYgKGluc3RhbGxhdGlvbklkKSB7XG4gICAgb3JRdWVyaWVzLnB1c2goe1xuICAgICAgaW5zdGFsbGF0aW9uSWQ6IGluc3RhbGxhdGlvbklkLFxuICAgIH0pO1xuICB9XG4gIGlmICh0aGlzLmRhdGEuZGV2aWNlVG9rZW4pIHtcbiAgICBvclF1ZXJpZXMucHVzaCh7IGRldmljZVRva2VuOiB0aGlzLmRhdGEuZGV2aWNlVG9rZW4gfSk7XG4gIH1cblxuICBpZiAob3JRdWVyaWVzLmxlbmd0aCA9PSAwKSB7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgcHJvbWlzZSA9IHByb21pc2VcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy5jb25maWcuZGF0YWJhc2UuZmluZChcbiAgICAgICAgJ19JbnN0YWxsYXRpb24nLFxuICAgICAgICB7XG4gICAgICAgICAgJG9yOiBvclF1ZXJpZXMsXG4gICAgICAgIH0sXG4gICAgICAgIHt9XG4gICAgICApO1xuICAgIH0pXG4gICAgLnRoZW4ocmVzdWx0cyA9PiB7XG4gICAgICByZXN1bHRzLmZvckVhY2gocmVzdWx0ID0+IHtcbiAgICAgICAgaWYgKHRoaXMucXVlcnkgJiYgdGhpcy5xdWVyeS5vYmplY3RJZCAmJiByZXN1bHQub2JqZWN0SWQgPT0gdGhpcy5xdWVyeS5vYmplY3RJZCkge1xuICAgICAgICAgIG9iamVjdElkTWF0Y2ggPSByZXN1bHQ7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHJlc3VsdC5pbnN0YWxsYXRpb25JZCA9PSBpbnN0YWxsYXRpb25JZCkge1xuICAgICAgICAgIGluc3RhbGxhdGlvbklkTWF0Y2ggPSByZXN1bHQ7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHJlc3VsdC5kZXZpY2VUb2tlbiA9PSB0aGlzLmRhdGEuZGV2aWNlVG9rZW4pIHtcbiAgICAgICAgICBkZXZpY2VUb2tlbk1hdGNoZXMucHVzaChyZXN1bHQpO1xuICAgICAgICB9XG4gICAgICB9KTtcblxuICAgICAgLy8gU2FuaXR5IGNoZWNrcyB3aGVuIHJ1bm5pbmcgYSBxdWVyeVxuICAgICAgaWYgKHRoaXMucXVlcnkgJiYgdGhpcy5xdWVyeS5vYmplY3RJZCkge1xuICAgICAgICBpZiAoIW9iamVjdElkTWF0Y2gpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuT0JKRUNUX05PVF9GT1VORCwgJ09iamVjdCBub3QgZm91bmQgZm9yIHVwZGF0ZS4nKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoXG4gICAgICAgICAgdGhpcy5kYXRhLmluc3RhbGxhdGlvbklkICYmXG4gICAgICAgICAgb2JqZWN0SWRNYXRjaC5pbnN0YWxsYXRpb25JZCAmJlxuICAgICAgICAgIHRoaXMuZGF0YS5pbnN0YWxsYXRpb25JZCAhPT0gb2JqZWN0SWRNYXRjaC5pbnN0YWxsYXRpb25JZFxuICAgICAgICApIHtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoMTM2LCAnaW5zdGFsbGF0aW9uSWQgbWF5IG5vdCBiZSBjaGFuZ2VkIGluIHRoaXMgJyArICdvcGVyYXRpb24nKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoXG4gICAgICAgICAgdGhpcy5kYXRhLmRldmljZVRva2VuICYmXG4gICAgICAgICAgb2JqZWN0SWRNYXRjaC5kZXZpY2VUb2tlbiAmJlxuICAgICAgICAgIHRoaXMuZGF0YS5kZXZpY2VUb2tlbiAhPT0gb2JqZWN0SWRNYXRjaC5kZXZpY2VUb2tlbiAmJlxuICAgICAgICAgICF0aGlzLmRhdGEuaW5zdGFsbGF0aW9uSWQgJiZcbiAgICAgICAgICAhb2JqZWN0SWRNYXRjaC5pbnN0YWxsYXRpb25JZFxuICAgICAgICApIHtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoMTM2LCAnZGV2aWNlVG9rZW4gbWF5IG5vdCBiZSBjaGFuZ2VkIGluIHRoaXMgJyArICdvcGVyYXRpb24nKTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoXG4gICAgICAgICAgdGhpcy5kYXRhLmRldmljZVR5cGUgJiZcbiAgICAgICAgICB0aGlzLmRhdGEuZGV2aWNlVHlwZSAmJlxuICAgICAgICAgIHRoaXMuZGF0YS5kZXZpY2VUeXBlICE9PSBvYmplY3RJZE1hdGNoLmRldmljZVR5cGVcbiAgICAgICAgKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKDEzNiwgJ2RldmljZVR5cGUgbWF5IG5vdCBiZSBjaGFuZ2VkIGluIHRoaXMgJyArICdvcGVyYXRpb24nKTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAodGhpcy5xdWVyeSAmJiB0aGlzLnF1ZXJ5Lm9iamVjdElkICYmIG9iamVjdElkTWF0Y2gpIHtcbiAgICAgICAgaWRNYXRjaCA9IG9iamVjdElkTWF0Y2g7XG4gICAgICB9XG5cbiAgICAgIGlmIChpbnN0YWxsYXRpb25JZCAmJiBpbnN0YWxsYXRpb25JZE1hdGNoKSB7XG4gICAgICAgIGlkTWF0Y2ggPSBpbnN0YWxsYXRpb25JZE1hdGNoO1xuICAgICAgfVxuICAgICAgLy8gbmVlZCB0byBzcGVjaWZ5IGRldmljZVR5cGUgb25seSBpZiBpdCdzIG5ld1xuICAgICAgaWYgKCF0aGlzLnF1ZXJ5ICYmICF0aGlzLmRhdGEuZGV2aWNlVHlwZSAmJiAhaWRNYXRjaCkge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoMTM1LCAnZGV2aWNlVHlwZSBtdXN0IGJlIHNwZWNpZmllZCBpbiB0aGlzIG9wZXJhdGlvbicpO1xuICAgICAgfVxuICAgIH0pXG4gICAgLnRoZW4oKCkgPT4ge1xuICAgICAgaWYgKCFpZE1hdGNoKSB7XG4gICAgICAgIGlmICghZGV2aWNlVG9rZW5NYXRjaGVzLmxlbmd0aCkge1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfSBlbHNlIGlmIChcbiAgICAgICAgICBkZXZpY2VUb2tlbk1hdGNoZXMubGVuZ3RoID09IDEgJiZcbiAgICAgICAgICAoIWRldmljZVRva2VuTWF0Y2hlc1swXVsnaW5zdGFsbGF0aW9uSWQnXSB8fCAhaW5zdGFsbGF0aW9uSWQpXG4gICAgICAgICkge1xuICAgICAgICAgIC8vIFNpbmdsZSBtYXRjaCBvbiBkZXZpY2UgdG9rZW4gYnV0IG5vbmUgb24gaW5zdGFsbGF0aW9uSWQsIGFuZCBlaXRoZXJcbiAgICAgICAgICAvLyB0aGUgcGFzc2VkIG9iamVjdCBvciB0aGUgbWF0Y2ggaXMgbWlzc2luZyBhbiBpbnN0YWxsYXRpb25JZCwgc28gd2VcbiAgICAgICAgICAvLyBjYW4ganVzdCByZXR1cm4gdGhlIG1hdGNoLlxuICAgICAgICAgIHJldHVybiBkZXZpY2VUb2tlbk1hdGNoZXNbMF1bJ29iamVjdElkJ107XG4gICAgICAgIH0gZWxzZSBpZiAoIXRoaXMuZGF0YS5pbnN0YWxsYXRpb25JZCkge1xuICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgIDEzMixcbiAgICAgICAgICAgICdNdXN0IHNwZWNpZnkgaW5zdGFsbGF0aW9uSWQgd2hlbiBkZXZpY2VUb2tlbiAnICtcbiAgICAgICAgICAgICAgJ21hdGNoZXMgbXVsdGlwbGUgSW5zdGFsbGF0aW9uIG9iamVjdHMnXG4gICAgICAgICAgKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAvLyBNdWx0aXBsZSBkZXZpY2UgdG9rZW4gbWF0Y2hlcyBhbmQgd2Ugc3BlY2lmaWVkIGFuIGluc3RhbGxhdGlvbiBJRCxcbiAgICAgICAgICAvLyBvciBhIHNpbmdsZSBtYXRjaCB3aGVyZSBib3RoIHRoZSBwYXNzZWQgYW5kIG1hdGNoaW5nIG9iamVjdHMgaGF2ZVxuICAgICAgICAgIC8vIGFuIGluc3RhbGxhdGlvbiBJRC4gVHJ5IGNsZWFuaW5nIG91dCBvbGQgaW5zdGFsbGF0aW9ucyB0aGF0IG1hdGNoXG4gICAgICAgICAgLy8gdGhlIGRldmljZVRva2VuLCBhbmQgcmV0dXJuIG5pbCB0byBzaWduYWwgdGhhdCBhIG5ldyBvYmplY3Qgc2hvdWxkXG4gICAgICAgICAgLy8gYmUgY3JlYXRlZC5cbiAgICAgICAgICB2YXIgZGVsUXVlcnkgPSB7XG4gICAgICAgICAgICBkZXZpY2VUb2tlbjogdGhpcy5kYXRhLmRldmljZVRva2VuLFxuICAgICAgICAgICAgaW5zdGFsbGF0aW9uSWQ6IHtcbiAgICAgICAgICAgICAgJG5lOiBpbnN0YWxsYXRpb25JZCxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfTtcbiAgICAgICAgICBpZiAodGhpcy5kYXRhLmFwcElkZW50aWZpZXIpIHtcbiAgICAgICAgICAgIGRlbFF1ZXJ5WydhcHBJZGVudGlmaWVyJ10gPSB0aGlzLmRhdGEuYXBwSWRlbnRpZmllcjtcbiAgICAgICAgICB9XG4gICAgICAgICAgdGhpcy5jb25maWcuZGF0YWJhc2UuZGVzdHJveSgnX0luc3RhbGxhdGlvbicsIGRlbFF1ZXJ5KS5jYXRjaChlcnIgPT4ge1xuICAgICAgICAgICAgaWYgKGVyci5jb2RlID09IFBhcnNlLkVycm9yLk9CSkVDVF9OT1RfRk9VTkQpIHtcbiAgICAgICAgICAgICAgLy8gbm8gZGVsZXRpb25zIHdlcmUgbWFkZS4gQ2FuIGJlIGlnbm9yZWQuXG4gICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIC8vIHJldGhyb3cgdGhlIGVycm9yXG4gICAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgICAgfSk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBpZiAoZGV2aWNlVG9rZW5NYXRjaGVzLmxlbmd0aCA9PSAxICYmICFkZXZpY2VUb2tlbk1hdGNoZXNbMF1bJ2luc3RhbGxhdGlvbklkJ10pIHtcbiAgICAgICAgICAvLyBFeGFjdGx5IG9uZSBkZXZpY2UgdG9rZW4gbWF0Y2ggYW5kIGl0IGRvZXNuJ3QgaGF2ZSBhbiBpbnN0YWxsYXRpb25cbiAgICAgICAgICAvLyBJRC4gVGhpcyBpcyB0aGUgb25lIGNhc2Ugd2hlcmUgd2Ugd2FudCB0byBtZXJnZSB3aXRoIHRoZSBleGlzdGluZ1xuICAgICAgICAgIC8vIG9iamVjdC5cbiAgICAgICAgICBjb25zdCBkZWxRdWVyeSA9IHsgb2JqZWN0SWQ6IGlkTWF0Y2gub2JqZWN0SWQgfTtcbiAgICAgICAgICByZXR1cm4gdGhpcy5jb25maWcuZGF0YWJhc2VcbiAgICAgICAgICAgIC5kZXN0cm95KCdfSW5zdGFsbGF0aW9uJywgZGVsUXVlcnkpXG4gICAgICAgICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgICAgICAgIHJldHVybiBkZXZpY2VUb2tlbk1hdGNoZXNbMF1bJ29iamVjdElkJ107XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgLmNhdGNoKGVyciA9PiB7XG4gICAgICAgICAgICAgIGlmIChlcnIuY29kZSA9PSBQYXJzZS5FcnJvci5PQkpFQ1RfTk9UX0ZPVU5EKSB7XG4gICAgICAgICAgICAgICAgLy8gbm8gZGVsZXRpb25zIHdlcmUgbWFkZS4gQ2FuIGJlIGlnbm9yZWRcbiAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgLy8gcmV0aHJvdyB0aGUgZXJyb3JcbiAgICAgICAgICAgICAgdGhyb3cgZXJyO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgaWYgKHRoaXMuZGF0YS5kZXZpY2VUb2tlbiAmJiBpZE1hdGNoLmRldmljZVRva2VuICE9IHRoaXMuZGF0YS5kZXZpY2VUb2tlbikge1xuICAgICAgICAgICAgLy8gV2UncmUgc2V0dGluZyB0aGUgZGV2aWNlIHRva2VuIG9uIGFuIGV4aXN0aW5nIGluc3RhbGxhdGlvbiwgc29cbiAgICAgICAgICAgIC8vIHdlIHNob3VsZCB0cnkgY2xlYW5pbmcgb3V0IG9sZCBpbnN0YWxsYXRpb25zIHRoYXQgbWF0Y2ggdGhpc1xuICAgICAgICAgICAgLy8gZGV2aWNlIHRva2VuLlxuICAgICAgICAgICAgY29uc3QgZGVsUXVlcnkgPSB7XG4gICAgICAgICAgICAgIGRldmljZVRva2VuOiB0aGlzLmRhdGEuZGV2aWNlVG9rZW4sXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgLy8gV2UgaGF2ZSBhIHVuaXF1ZSBpbnN0YWxsIElkLCB1c2UgdGhhdCB0byBwcmVzZXJ2ZVxuICAgICAgICAgICAgLy8gdGhlIGludGVyZXN0aW5nIGluc3RhbGxhdGlvblxuICAgICAgICAgICAgaWYgKHRoaXMuZGF0YS5pbnN0YWxsYXRpb25JZCkge1xuICAgICAgICAgICAgICBkZWxRdWVyeVsnaW5zdGFsbGF0aW9uSWQnXSA9IHtcbiAgICAgICAgICAgICAgICAkbmU6IHRoaXMuZGF0YS5pbnN0YWxsYXRpb25JZCxcbiAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIH0gZWxzZSBpZiAoXG4gICAgICAgICAgICAgIGlkTWF0Y2gub2JqZWN0SWQgJiZcbiAgICAgICAgICAgICAgdGhpcy5kYXRhLm9iamVjdElkICYmXG4gICAgICAgICAgICAgIGlkTWF0Y2gub2JqZWN0SWQgPT0gdGhpcy5kYXRhLm9iamVjdElkXG4gICAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgLy8gd2UgcGFzc2VkIGFuIG9iamVjdElkLCBwcmVzZXJ2ZSB0aGF0IGluc3RhbGF0aW9uXG4gICAgICAgICAgICAgIGRlbFF1ZXJ5WydvYmplY3RJZCddID0ge1xuICAgICAgICAgICAgICAgICRuZTogaWRNYXRjaC5vYmplY3RJZCxcbiAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIC8vIFdoYXQgdG8gZG8gaGVyZT8gY2FuJ3QgcmVhbGx5IGNsZWFuIHVwIGV2ZXJ5dGhpbmcuLi5cbiAgICAgICAgICAgICAgcmV0dXJuIGlkTWF0Y2gub2JqZWN0SWQ7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAodGhpcy5kYXRhLmFwcElkZW50aWZpZXIpIHtcbiAgICAgICAgICAgICAgZGVsUXVlcnlbJ2FwcElkZW50aWZpZXInXSA9IHRoaXMuZGF0YS5hcHBJZGVudGlmaWVyO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdGhpcy5jb25maWcuZGF0YWJhc2UuZGVzdHJveSgnX0luc3RhbGxhdGlvbicsIGRlbFF1ZXJ5KS5jYXRjaChlcnIgPT4ge1xuICAgICAgICAgICAgICBpZiAoZXJyLmNvZGUgPT0gUGFyc2UuRXJyb3IuT0JKRUNUX05PVF9GT1VORCkge1xuICAgICAgICAgICAgICAgIC8vIG5vIGRlbGV0aW9ucyB3ZXJlIG1hZGUuIENhbiBiZSBpZ25vcmVkLlxuICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAvLyByZXRocm93IHRoZSBlcnJvclxuICAgICAgICAgICAgICB0aHJvdyBlcnI7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgLy8gSW4gbm9uLW1lcmdlIHNjZW5hcmlvcywganVzdCByZXR1cm4gdGhlIGluc3RhbGxhdGlvbiBtYXRjaCBpZFxuICAgICAgICAgIHJldHVybiBpZE1hdGNoLm9iamVjdElkO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSlcbiAgICAudGhlbihvYmpJZCA9PiB7XG4gICAgICBpZiAob2JqSWQpIHtcbiAgICAgICAgdGhpcy5xdWVyeSA9IHsgb2JqZWN0SWQ6IG9iaklkIH07XG4gICAgICAgIGRlbGV0ZSB0aGlzLmRhdGEub2JqZWN0SWQ7XG4gICAgICAgIGRlbGV0ZSB0aGlzLmRhdGEuY3JlYXRlZEF0O1xuICAgICAgfVxuICAgICAgLy8gVE9ETzogVmFsaWRhdGUgb3BzIChhZGQvcmVtb3ZlIG9uIGNoYW5uZWxzLCAkaW5jIG9uIGJhZGdlLCBldGMuKVxuICAgIH0pO1xuICByZXR1cm4gcHJvbWlzZTtcbn07XG5cbi8vIElmIHdlIHNob3J0LWNpcmN1aXRlZCB0aGUgb2JqZWN0IHJlc3BvbnNlIC0gdGhlbiB3ZSBuZWVkIHRvIG1ha2Ugc3VyZSB3ZSBleHBhbmQgYWxsIHRoZSBmaWxlcyxcbi8vIHNpbmNlIHRoaXMgbWlnaHQgbm90IGhhdmUgYSBxdWVyeSwgbWVhbmluZyBpdCB3b24ndCByZXR1cm4gdGhlIGZ1bGwgcmVzdWx0IGJhY2suXG4vLyBUT0RPOiAobmx1dHNlbmtvKSBUaGlzIHNob3VsZCBkaWUgd2hlbiB3ZSBtb3ZlIHRvIHBlci1jbGFzcyBiYXNlZCBjb250cm9sbGVycyBvbiBfU2Vzc2lvbi9fVXNlclxuUmVzdFdyaXRlLnByb3RvdHlwZS5leHBhbmRGaWxlc0ZvckV4aXN0aW5nT2JqZWN0cyA9IGZ1bmN0aW9uICgpIHtcbiAgLy8gQ2hlY2sgd2hldGhlciB3ZSBoYXZlIGEgc2hvcnQtY2lyY3VpdGVkIHJlc3BvbnNlIC0gb25seSB0aGVuIHJ1biBleHBhbnNpb24uXG4gIGlmICh0aGlzLnJlc3BvbnNlICYmIHRoaXMucmVzcG9uc2UucmVzcG9uc2UpIHtcbiAgICB0aGlzLmNvbmZpZy5maWxlc0NvbnRyb2xsZXIuZXhwYW5kRmlsZXNJbk9iamVjdCh0aGlzLmNvbmZpZywgdGhpcy5yZXNwb25zZS5yZXNwb25zZSk7XG4gIH1cbn07XG5cblJlc3RXcml0ZS5wcm90b3R5cGUucnVuRGF0YWJhc2VPcGVyYXRpb24gPSBmdW5jdGlvbiAoKSB7XG4gIGlmICh0aGlzLnJlc3BvbnNlKSB7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgaWYgKHRoaXMuY2xhc3NOYW1lID09PSAnX1JvbGUnKSB7XG4gICAgdGhpcy5jb25maWcuY2FjaGVDb250cm9sbGVyLnJvbGUuY2xlYXIoKTtcbiAgfVxuXG4gIGlmICh0aGlzLmNsYXNzTmFtZSA9PT0gJ19Vc2VyJyAmJiB0aGlzLnF1ZXJ5ICYmIHRoaXMuYXV0aC5pc1VuYXV0aGVudGljYXRlZCgpKSB7XG4gICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgUGFyc2UuRXJyb3IuU0VTU0lPTl9NSVNTSU5HLFxuICAgICAgYENhbm5vdCBtb2RpZnkgdXNlciAke3RoaXMucXVlcnkub2JqZWN0SWR9LmBcbiAgICApO1xuICB9XG5cbiAgaWYgKHRoaXMuY2xhc3NOYW1lID09PSAnX1Byb2R1Y3QnICYmIHRoaXMuZGF0YS5kb3dubG9hZCkge1xuICAgIHRoaXMuZGF0YS5kb3dubG9hZE5hbWUgPSB0aGlzLmRhdGEuZG93bmxvYWQubmFtZTtcbiAgfVxuXG4gIC8vIFRPRE86IEFkZCBiZXR0ZXIgZGV0ZWN0aW9uIGZvciBBQ0wsIGVuc3VyaW5nIGEgdXNlciBjYW4ndCBiZSBsb2NrZWQgZnJvbVxuICAvLyAgICAgICB0aGVpciBvd24gdXNlciByZWNvcmQuXG4gIGlmICh0aGlzLmRhdGEuQUNMICYmIHRoaXMuZGF0YS5BQ0xbJyp1bnJlc29sdmVkJ10pIHtcbiAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9BQ0wsICdJbnZhbGlkIEFDTC4nKTtcbiAgfVxuXG4gIGlmICh0aGlzLnF1ZXJ5KSB7XG4gICAgLy8gRm9yY2UgdGhlIHVzZXIgdG8gbm90IGxvY2tvdXRcbiAgICAvLyBNYXRjaGVkIHdpdGggcGFyc2UuY29tXG4gICAgaWYgKHRoaXMuY2xhc3NOYW1lID09PSAnX1VzZXInICYmIHRoaXMuZGF0YS5BQ0wgJiYgdGhpcy5hdXRoLmlzTWFzdGVyICE9PSB0cnVlKSB7XG4gICAgICB0aGlzLmRhdGEuQUNMW3RoaXMucXVlcnkub2JqZWN0SWRdID0geyByZWFkOiB0cnVlLCB3cml0ZTogdHJ1ZSB9O1xuICAgIH1cbiAgICAvLyB1cGRhdGUgcGFzc3dvcmQgdGltZXN0YW1wIGlmIHVzZXIgcGFzc3dvcmQgaXMgYmVpbmcgY2hhbmdlZFxuICAgIGlmIChcbiAgICAgIHRoaXMuY2xhc3NOYW1lID09PSAnX1VzZXInICYmXG4gICAgICB0aGlzLmRhdGEuX2hhc2hlZF9wYXNzd29yZCAmJlxuICAgICAgdGhpcy5jb25maWcucGFzc3dvcmRQb2xpY3kgJiZcbiAgICAgIHRoaXMuY29uZmlnLnBhc3N3b3JkUG9saWN5Lm1heFBhc3N3b3JkQWdlXG4gICAgKSB7XG4gICAgICB0aGlzLmRhdGEuX3Bhc3N3b3JkX2NoYW5nZWRfYXQgPSBQYXJzZS5fZW5jb2RlKG5ldyBEYXRlKCkpO1xuICAgIH1cbiAgICAvLyBJZ25vcmUgY3JlYXRlZEF0IHdoZW4gdXBkYXRlXG4gICAgZGVsZXRlIHRoaXMuZGF0YS5jcmVhdGVkQXQ7XG5cbiAgICBsZXQgZGVmZXIgPSBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAvLyBpZiBwYXNzd29yZCBoaXN0b3J5IGlzIGVuYWJsZWQgdGhlbiBzYXZlIHRoZSBjdXJyZW50IHBhc3N3b3JkIHRvIGhpc3RvcnlcbiAgICBpZiAoXG4gICAgICB0aGlzLmNsYXNzTmFtZSA9PT0gJ19Vc2VyJyAmJlxuICAgICAgdGhpcy5kYXRhLl9oYXNoZWRfcGFzc3dvcmQgJiZcbiAgICAgIHRoaXMuY29uZmlnLnBhc3N3b3JkUG9saWN5ICYmXG4gICAgICB0aGlzLmNvbmZpZy5wYXNzd29yZFBvbGljeS5tYXhQYXNzd29yZEhpc3RvcnlcbiAgICApIHtcbiAgICAgIGRlZmVyID0gdGhpcy5jb25maWcuZGF0YWJhc2VcbiAgICAgICAgLmZpbmQoXG4gICAgICAgICAgJ19Vc2VyJyxcbiAgICAgICAgICB7IG9iamVjdElkOiB0aGlzLm9iamVjdElkKCkgfSxcbiAgICAgICAgICB7IGtleXM6IFsnX3Bhc3N3b3JkX2hpc3RvcnknLCAnX2hhc2hlZF9wYXNzd29yZCddIH1cbiAgICAgICAgKVxuICAgICAgICAudGhlbihyZXN1bHRzID0+IHtcbiAgICAgICAgICBpZiAocmVzdWx0cy5sZW5ndGggIT0gMSkge1xuICAgICAgICAgICAgdGhyb3cgdW5kZWZpbmVkO1xuICAgICAgICAgIH1cbiAgICAgICAgICBjb25zdCB1c2VyID0gcmVzdWx0c1swXTtcbiAgICAgICAgICBsZXQgb2xkUGFzc3dvcmRzID0gW107XG4gICAgICAgICAgaWYgKHVzZXIuX3Bhc3N3b3JkX2hpc3RvcnkpIHtcbiAgICAgICAgICAgIG9sZFBhc3N3b3JkcyA9IF8udGFrZShcbiAgICAgICAgICAgICAgdXNlci5fcGFzc3dvcmRfaGlzdG9yeSxcbiAgICAgICAgICAgICAgdGhpcy5jb25maWcucGFzc3dvcmRQb2xpY3kubWF4UGFzc3dvcmRIaXN0b3J5XG4gICAgICAgICAgICApO1xuICAgICAgICAgIH1cbiAgICAgICAgICAvL24tMSBwYXNzd29yZHMgZ28gaW50byBoaXN0b3J5IGluY2x1ZGluZyBsYXN0IHBhc3N3b3JkXG4gICAgICAgICAgd2hpbGUgKFxuICAgICAgICAgICAgb2xkUGFzc3dvcmRzLmxlbmd0aCA+IE1hdGgubWF4KDAsIHRoaXMuY29uZmlnLnBhc3N3b3JkUG9saWN5Lm1heFBhc3N3b3JkSGlzdG9yeSAtIDIpXG4gICAgICAgICAgKSB7XG4gICAgICAgICAgICBvbGRQYXNzd29yZHMuc2hpZnQoKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgb2xkUGFzc3dvcmRzLnB1c2godXNlci5wYXNzd29yZCk7XG4gICAgICAgICAgdGhpcy5kYXRhLl9wYXNzd29yZF9oaXN0b3J5ID0gb2xkUGFzc3dvcmRzO1xuICAgICAgICB9KTtcbiAgICB9XG5cbiAgICByZXR1cm4gZGVmZXIudGhlbigoKSA9PiB7XG4gICAgICAvLyBSdW4gYW4gdXBkYXRlXG4gICAgICByZXR1cm4gdGhpcy5jb25maWcuZGF0YWJhc2VcbiAgICAgICAgLnVwZGF0ZShcbiAgICAgICAgICB0aGlzLmNsYXNzTmFtZSxcbiAgICAgICAgICB0aGlzLnF1ZXJ5LFxuICAgICAgICAgIHRoaXMuZGF0YSxcbiAgICAgICAgICB0aGlzLnJ1bk9wdGlvbnMsXG4gICAgICAgICAgZmFsc2UsXG4gICAgICAgICAgZmFsc2UsXG4gICAgICAgICAgdGhpcy52YWxpZFNjaGVtYUNvbnRyb2xsZXJcbiAgICAgICAgKVxuICAgICAgICAudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICAgICAgcmVzcG9uc2UudXBkYXRlZEF0ID0gdGhpcy51cGRhdGVkQXQ7XG4gICAgICAgICAgdGhpcy5fdXBkYXRlUmVzcG9uc2VXaXRoRGF0YShyZXNwb25zZSwgdGhpcy5kYXRhKTtcbiAgICAgICAgICB0aGlzLnJlc3BvbnNlID0geyByZXNwb25zZSB9O1xuICAgICAgICB9KTtcbiAgICB9KTtcbiAgfSBlbHNlIHtcbiAgICAvLyBTZXQgdGhlIGRlZmF1bHQgQUNMIGFuZCBwYXNzd29yZCB0aW1lc3RhbXAgZm9yIHRoZSBuZXcgX1VzZXJcbiAgICBpZiAodGhpcy5jbGFzc05hbWUgPT09ICdfVXNlcicpIHtcbiAgICAgIHZhciBBQ0wgPSB0aGlzLmRhdGEuQUNMO1xuICAgICAgLy8gZGVmYXVsdCBwdWJsaWMgci93IEFDTFxuICAgICAgaWYgKCFBQ0wpIHtcbiAgICAgICAgQUNMID0ge307XG4gICAgICAgIEFDTFsnKiddID0geyByZWFkOiB0cnVlLCB3cml0ZTogZmFsc2UgfTtcbiAgICAgIH1cbiAgICAgIC8vIG1ha2Ugc3VyZSB0aGUgdXNlciBpcyBub3QgbG9ja2VkIGRvd25cbiAgICAgIEFDTFt0aGlzLmRhdGEub2JqZWN0SWRdID0geyByZWFkOiB0cnVlLCB3cml0ZTogdHJ1ZSB9O1xuICAgICAgdGhpcy5kYXRhLkFDTCA9IEFDTDtcbiAgICAgIC8vIHBhc3N3b3JkIHRpbWVzdGFtcCB0byBiZSB1c2VkIHdoZW4gcGFzc3dvcmQgZXhwaXJ5IHBvbGljeSBpcyBlbmZvcmNlZFxuICAgICAgaWYgKHRoaXMuY29uZmlnLnBhc3N3b3JkUG9saWN5ICYmIHRoaXMuY29uZmlnLnBhc3N3b3JkUG9saWN5Lm1heFBhc3N3b3JkQWdlKSB7XG4gICAgICAgIHRoaXMuZGF0YS5fcGFzc3dvcmRfY2hhbmdlZF9hdCA9IFBhcnNlLl9lbmNvZGUobmV3IERhdGUoKSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gUnVuIGEgY3JlYXRlXG4gICAgcmV0dXJuIHRoaXMuY29uZmlnLmRhdGFiYXNlXG4gICAgICAuY3JlYXRlKHRoaXMuY2xhc3NOYW1lLCB0aGlzLmRhdGEsIHRoaXMucnVuT3B0aW9ucywgZmFsc2UsIHRoaXMudmFsaWRTY2hlbWFDb250cm9sbGVyKVxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgaWYgKHRoaXMuY2xhc3NOYW1lICE9PSAnX1VzZXInIHx8IGVycm9yLmNvZGUgIT09IFBhcnNlLkVycm9yLkRVUExJQ0FURV9WQUxVRSkge1xuICAgICAgICAgIHRocm93IGVycm9yO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gUXVpY2sgY2hlY2ssIGlmIHdlIHdlcmUgYWJsZSB0byBpbmZlciB0aGUgZHVwbGljYXRlZCBmaWVsZCBuYW1lXG4gICAgICAgIGlmIChlcnJvciAmJiBlcnJvci51c2VySW5mbyAmJiBlcnJvci51c2VySW5mby5kdXBsaWNhdGVkX2ZpZWxkID09PSAndXNlcm5hbWUnKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuVVNFUk5BTUVfVEFLRU4sXG4gICAgICAgICAgICAnQWNjb3VudCBhbHJlYWR5IGV4aXN0cyBmb3IgdGhpcyB1c2VybmFtZS4nXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChlcnJvciAmJiBlcnJvci51c2VySW5mbyAmJiBlcnJvci51c2VySW5mby5kdXBsaWNhdGVkX2ZpZWxkID09PSAnZW1haWwnKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuRU1BSUxfVEFLRU4sXG4gICAgICAgICAgICAnQWNjb3VudCBhbHJlYWR5IGV4aXN0cyBmb3IgdGhpcyBlbWFpbCBhZGRyZXNzLidcbiAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gSWYgdGhpcyB3YXMgYSBmYWlsZWQgdXNlciBjcmVhdGlvbiBkdWUgdG8gdXNlcm5hbWUgb3IgZW1haWwgYWxyZWFkeSB0YWtlbiwgd2UgbmVlZCB0b1xuICAgICAgICAvLyBjaGVjayB3aGV0aGVyIGl0IHdhcyB1c2VybmFtZSBvciBlbWFpbCBhbmQgcmV0dXJuIHRoZSBhcHByb3ByaWF0ZSBlcnJvci5cbiAgICAgICAgLy8gRmFsbGJhY2sgdG8gdGhlIG9yaWdpbmFsIG1ldGhvZFxuICAgICAgICAvLyBUT0RPOiBTZWUgaWYgd2UgY2FuIGxhdGVyIGRvIHRoaXMgd2l0aG91dCBhZGRpdGlvbmFsIHF1ZXJpZXMgYnkgdXNpbmcgbmFtZWQgaW5kZXhlcy5cbiAgICAgICAgcmV0dXJuIHRoaXMuY29uZmlnLmRhdGFiYXNlXG4gICAgICAgICAgLmZpbmQoXG4gICAgICAgICAgICB0aGlzLmNsYXNzTmFtZSxcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgdXNlcm5hbWU6IHRoaXMuZGF0YS51c2VybmFtZSxcbiAgICAgICAgICAgICAgb2JqZWN0SWQ6IHsgJG5lOiB0aGlzLm9iamVjdElkKCkgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB7IGxpbWl0OiAxIH1cbiAgICAgICAgICApXG4gICAgICAgICAgLnRoZW4ocmVzdWx0cyA9PiB7XG4gICAgICAgICAgICBpZiAocmVzdWx0cy5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgICAgICBQYXJzZS5FcnJvci5VU0VSTkFNRV9UQUtFTixcbiAgICAgICAgICAgICAgICAnQWNjb3VudCBhbHJlYWR5IGV4aXN0cyBmb3IgdGhpcyB1c2VybmFtZS4nXG4gICAgICAgICAgICAgICk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5jb25maWcuZGF0YWJhc2UuZmluZChcbiAgICAgICAgICAgICAgdGhpcy5jbGFzc05hbWUsXG4gICAgICAgICAgICAgIHsgZW1haWw6IHRoaXMuZGF0YS5lbWFpbCwgb2JqZWN0SWQ6IHsgJG5lOiB0aGlzLm9iamVjdElkKCkgfSB9LFxuICAgICAgICAgICAgICB7IGxpbWl0OiAxIH1cbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfSlcbiAgICAgICAgICAudGhlbihyZXN1bHRzID0+IHtcbiAgICAgICAgICAgIGlmIChyZXN1bHRzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICAgIFBhcnNlLkVycm9yLkVNQUlMX1RBS0VOLFxuICAgICAgICAgICAgICAgICdBY2NvdW50IGFscmVhZHkgZXhpc3RzIGZvciB0aGlzIGVtYWlsIGFkZHJlc3MuJ1xuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICBQYXJzZS5FcnJvci5EVVBMSUNBVEVfVkFMVUUsXG4gICAgICAgICAgICAgICdBIGR1cGxpY2F0ZSB2YWx1ZSBmb3IgYSBmaWVsZCB3aXRoIHVuaXF1ZSB2YWx1ZXMgd2FzIHByb3ZpZGVkJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9KTtcbiAgICAgIH0pXG4gICAgICAudGhlbihyZXNwb25zZSA9PiB7XG4gICAgICAgIHJlc3BvbnNlLm9iamVjdElkID0gdGhpcy5kYXRhLm9iamVjdElkO1xuICAgICAgICByZXNwb25zZS5jcmVhdGVkQXQgPSB0aGlzLmRhdGEuY3JlYXRlZEF0O1xuXG4gICAgICAgIGlmICh0aGlzLnJlc3BvbnNlU2hvdWxkSGF2ZVVzZXJuYW1lKSB7XG4gICAgICAgICAgcmVzcG9uc2UudXNlcm5hbWUgPSB0aGlzLmRhdGEudXNlcm5hbWU7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fdXBkYXRlUmVzcG9uc2VXaXRoRGF0YShyZXNwb25zZSwgdGhpcy5kYXRhKTtcbiAgICAgICAgdGhpcy5yZXNwb25zZSA9IHtcbiAgICAgICAgICBzdGF0dXM6IDIwMSxcbiAgICAgICAgICByZXNwb25zZSxcbiAgICAgICAgICBsb2NhdGlvbjogdGhpcy5sb2NhdGlvbigpLFxuICAgICAgICB9O1xuICAgICAgfSk7XG4gIH1cbn07XG5cbi8vIFJldHVybnMgbm90aGluZyAtIGRvZXNuJ3Qgd2FpdCBmb3IgdGhlIHRyaWdnZXIuXG5SZXN0V3JpdGUucHJvdG90eXBlLnJ1bkFmdGVyU2F2ZVRyaWdnZXIgPSBmdW5jdGlvbiAoKSB7XG4gIGlmICghdGhpcy5yZXNwb25zZSB8fCAhdGhpcy5yZXNwb25zZS5yZXNwb25zZSkge1xuICAgIHJldHVybjtcbiAgfVxuXG4gIC8vIEF2b2lkIGRvaW5nIGFueSBzZXR1cCBmb3IgdHJpZ2dlcnMgaWYgdGhlcmUgaXMgbm8gJ2FmdGVyU2F2ZScgdHJpZ2dlciBmb3IgdGhpcyBjbGFzcy5cbiAgY29uc3QgaGFzQWZ0ZXJTYXZlSG9vayA9IHRyaWdnZXJzLnRyaWdnZXJFeGlzdHMoXG4gICAgdGhpcy5jbGFzc05hbWUsXG4gICAgdHJpZ2dlcnMuVHlwZXMuYWZ0ZXJTYXZlLFxuICAgIHRoaXMuY29uZmlnLmFwcGxpY2F0aW9uSWRcbiAgKTtcbiAgY29uc3QgaGFzTGl2ZVF1ZXJ5ID0gdGhpcy5jb25maWcubGl2ZVF1ZXJ5Q29udHJvbGxlci5oYXNMaXZlUXVlcnkodGhpcy5jbGFzc05hbWUpO1xuICBpZiAoIWhhc0FmdGVyU2F2ZUhvb2sgJiYgIWhhc0xpdmVRdWVyeSkge1xuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgfVxuXG4gIHZhciBleHRyYURhdGEgPSB7IGNsYXNzTmFtZTogdGhpcy5jbGFzc05hbWUgfTtcbiAgaWYgKHRoaXMucXVlcnkgJiYgdGhpcy5xdWVyeS5vYmplY3RJZCkge1xuICAgIGV4dHJhRGF0YS5vYmplY3RJZCA9IHRoaXMucXVlcnkub2JqZWN0SWQ7XG4gIH1cblxuICAvLyBCdWlsZCB0aGUgb3JpZ2luYWwgb2JqZWN0LCB3ZSBvbmx5IGRvIHRoaXMgZm9yIGEgdXBkYXRlIHdyaXRlLlxuICBsZXQgb3JpZ2luYWxPYmplY3Q7XG4gIGlmICh0aGlzLnF1ZXJ5ICYmIHRoaXMucXVlcnkub2JqZWN0SWQpIHtcbiAgICBvcmlnaW5hbE9iamVjdCA9IHRyaWdnZXJzLmluZmxhdGUoZXh0cmFEYXRhLCB0aGlzLm9yaWdpbmFsRGF0YSk7XG4gIH1cblxuICAvLyBCdWlsZCB0aGUgaW5mbGF0ZWQgb2JqZWN0LCBkaWZmZXJlbnQgZnJvbSBiZWZvcmVTYXZlLCBvcmlnaW5hbERhdGEgaXMgbm90IGVtcHR5XG4gIC8vIHNpbmNlIGRldmVsb3BlcnMgY2FuIGNoYW5nZSBkYXRhIGluIHRoZSBiZWZvcmVTYXZlLlxuICBjb25zdCB1cGRhdGVkT2JqZWN0ID0gdGhpcy5idWlsZFVwZGF0ZWRPYmplY3QoZXh0cmFEYXRhKTtcbiAgdXBkYXRlZE9iamVjdC5faGFuZGxlU2F2ZVJlc3BvbnNlKHRoaXMucmVzcG9uc2UucmVzcG9uc2UsIHRoaXMucmVzcG9uc2Uuc3RhdHVzIHx8IDIwMCk7XG5cbiAgdGhpcy5jb25maWcuZGF0YWJhc2UubG9hZFNjaGVtYSgpLnRoZW4oc2NoZW1hQ29udHJvbGxlciA9PiB7XG4gICAgLy8gTm90aWZpeSBMaXZlUXVlcnlTZXJ2ZXIgaWYgcG9zc2libGVcbiAgICBjb25zdCBwZXJtcyA9IHNjaGVtYUNvbnRyb2xsZXIuZ2V0Q2xhc3NMZXZlbFBlcm1pc3Npb25zKHVwZGF0ZWRPYmplY3QuY2xhc3NOYW1lKTtcbiAgICB0aGlzLmNvbmZpZy5saXZlUXVlcnlDb250cm9sbGVyLm9uQWZ0ZXJTYXZlKFxuICAgICAgdXBkYXRlZE9iamVjdC5jbGFzc05hbWUsXG4gICAgICB1cGRhdGVkT2JqZWN0LFxuICAgICAgb3JpZ2luYWxPYmplY3QsXG4gICAgICBwZXJtc1xuICAgICk7XG4gIH0pO1xuXG4gIC8vIFJ1biBhZnRlclNhdmUgdHJpZ2dlclxuICByZXR1cm4gdHJpZ2dlcnNcbiAgICAubWF5YmVSdW5UcmlnZ2VyKFxuICAgICAgdHJpZ2dlcnMuVHlwZXMuYWZ0ZXJTYXZlLFxuICAgICAgdGhpcy5hdXRoLFxuICAgICAgdXBkYXRlZE9iamVjdCxcbiAgICAgIG9yaWdpbmFsT2JqZWN0LFxuICAgICAgdGhpcy5jb25maWcsXG4gICAgICB0aGlzLmNvbnRleHRcbiAgICApXG4gICAgLnRoZW4ocmVzdWx0ID0+IHtcbiAgICAgIGlmIChyZXN1bHQgJiYgdHlwZW9mIHJlc3VsdCA9PT0gJ29iamVjdCcpIHtcbiAgICAgICAgdGhpcy5yZXNwb25zZS5yZXNwb25zZSA9IHJlc3VsdDtcbiAgICAgIH1cbiAgICB9KVxuICAgIC5jYXRjaChmdW5jdGlvbiAoZXJyKSB7XG4gICAgICBsb2dnZXIud2FybignYWZ0ZXJTYXZlIGNhdWdodCBhbiBlcnJvcicsIGVycik7XG4gICAgfSk7XG59O1xuXG4vLyBBIGhlbHBlciB0byBmaWd1cmUgb3V0IHdoYXQgbG9jYXRpb24gdGhpcyBvcGVyYXRpb24gaGFwcGVucyBhdC5cblJlc3RXcml0ZS5wcm90b3R5cGUubG9jYXRpb24gPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBtaWRkbGUgPSB0aGlzLmNsYXNzTmFtZSA9PT0gJ19Vc2VyJyA/ICcvdXNlcnMvJyA6ICcvY2xhc3Nlcy8nICsgdGhpcy5jbGFzc05hbWUgKyAnLyc7XG4gIGNvbnN0IG1vdW50ID0gdGhpcy5jb25maWcubW91bnQgfHwgdGhpcy5jb25maWcuc2VydmVyVVJMO1xuICByZXR1cm4gbW91bnQgKyBtaWRkbGUgKyB0aGlzLmRhdGEub2JqZWN0SWQ7XG59O1xuXG4vLyBBIGhlbHBlciB0byBnZXQgdGhlIG9iamVjdCBpZCBmb3IgdGhpcyBvcGVyYXRpb24uXG4vLyBCZWNhdXNlIGl0IGNvdWxkIGJlIGVpdGhlciBvbiB0aGUgcXVlcnkgb3Igb24gdGhlIGRhdGFcblJlc3RXcml0ZS5wcm90b3R5cGUub2JqZWN0SWQgPSBmdW5jdGlvbiAoKSB7XG4gIHJldHVybiB0aGlzLmRhdGEub2JqZWN0SWQgfHwgdGhpcy5xdWVyeS5vYmplY3RJZDtcbn07XG5cbi8vIFJldHVybnMgYSBjb3B5IG9mIHRoZSBkYXRhIGFuZCBkZWxldGUgYmFkIGtleXMgKF9hdXRoX2RhdGEsIF9oYXNoZWRfcGFzc3dvcmQuLi4pXG5SZXN0V3JpdGUucHJvdG90eXBlLnNhbml0aXplZERhdGEgPSBmdW5jdGlvbiAoKSB7XG4gIGNvbnN0IGRhdGEgPSBPYmplY3Qua2V5cyh0aGlzLmRhdGEpLnJlZHVjZSgoZGF0YSwga2V5KSA9PiB7XG4gICAgLy8gUmVnZXhwIGNvbWVzIGZyb20gUGFyc2UuT2JqZWN0LnByb3RvdHlwZS52YWxpZGF0ZVxuICAgIGlmICghL15bQS1aYS16XVswLTlBLVphLXpfXSokLy50ZXN0KGtleSkpIHtcbiAgICAgIGRlbGV0ZSBkYXRhW2tleV07XG4gICAgfVxuICAgIHJldHVybiBkYXRhO1xuICB9LCBkZWVwY29weSh0aGlzLmRhdGEpKTtcbiAgcmV0dXJuIFBhcnNlLl9kZWNvZGUodW5kZWZpbmVkLCBkYXRhKTtcbn07XG5cbi8vIFJldHVybnMgYW4gdXBkYXRlZCBjb3B5IG9mIHRoZSBvYmplY3RcblJlc3RXcml0ZS5wcm90b3R5cGUuYnVpbGRVcGRhdGVkT2JqZWN0ID0gZnVuY3Rpb24gKGV4dHJhRGF0YSkge1xuICBjb25zdCB1cGRhdGVkT2JqZWN0ID0gdHJpZ2dlcnMuaW5mbGF0ZShleHRyYURhdGEsIHRoaXMub3JpZ2luYWxEYXRhKTtcbiAgT2JqZWN0LmtleXModGhpcy5kYXRhKS5yZWR1Y2UoZnVuY3Rpb24gKGRhdGEsIGtleSkge1xuICAgIGlmIChrZXkuaW5kZXhPZignLicpID4gMCkge1xuICAgICAgaWYgKHR5cGVvZiBkYXRhW2tleV0uX19vcCA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgdXBkYXRlZE9iamVjdC5zZXQoa2V5LCBkYXRhW2tleV0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gc3ViZG9jdW1lbnQga2V5IHdpdGggZG90IG5vdGF0aW9uIHsgJ3gueSc6IHYgfSA9PiB7ICd4JzogeyAneScgOiB2IH0gfSlcbiAgICAgICAgY29uc3Qgc3BsaXR0ZWRLZXkgPSBrZXkuc3BsaXQoJy4nKTtcbiAgICAgICAgY29uc3QgcGFyZW50UHJvcCA9IHNwbGl0dGVkS2V5WzBdO1xuICAgICAgICBsZXQgcGFyZW50VmFsID0gdXBkYXRlZE9iamVjdC5nZXQocGFyZW50UHJvcCk7XG4gICAgICAgIGlmICh0eXBlb2YgcGFyZW50VmFsICE9PSAnb2JqZWN0Jykge1xuICAgICAgICAgIHBhcmVudFZhbCA9IHt9O1xuICAgICAgICB9XG4gICAgICAgIHBhcmVudFZhbFtzcGxpdHRlZEtleVsxXV0gPSBkYXRhW2tleV07XG4gICAgICAgIHVwZGF0ZWRPYmplY3Quc2V0KHBhcmVudFByb3AsIHBhcmVudFZhbCk7XG4gICAgICB9XG4gICAgICBkZWxldGUgZGF0YVtrZXldO1xuICAgIH1cbiAgICByZXR1cm4gZGF0YTtcbiAgfSwgZGVlcGNvcHkodGhpcy5kYXRhKSk7XG5cbiAgdXBkYXRlZE9iamVjdC5zZXQodGhpcy5zYW5pdGl6ZWREYXRhKCkpO1xuICByZXR1cm4gdXBkYXRlZE9iamVjdDtcbn07XG5cblJlc3RXcml0ZS5wcm90b3R5cGUuY2xlYW5Vc2VyQXV0aERhdGEgPSBmdW5jdGlvbiAoKSB7XG4gIGlmICh0aGlzLnJlc3BvbnNlICYmIHRoaXMucmVzcG9uc2UucmVzcG9uc2UgJiYgdGhpcy5jbGFzc05hbWUgPT09ICdfVXNlcicpIHtcbiAgICBjb25zdCB1c2VyID0gdGhpcy5yZXNwb25zZS5yZXNwb25zZTtcbiAgICBpZiAodXNlci5hdXRoRGF0YSkge1xuICAgICAgT2JqZWN0LmtleXModXNlci5hdXRoRGF0YSkuZm9yRWFjaChwcm92aWRlciA9PiB7XG4gICAgICAgIGlmICh1c2VyLmF1dGhEYXRhW3Byb3ZpZGVyXSA9PT0gbnVsbCkge1xuICAgICAgICAgIGRlbGV0ZSB1c2VyLmF1dGhEYXRhW3Byb3ZpZGVyXTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgICBpZiAoT2JqZWN0LmtleXModXNlci5hdXRoRGF0YSkubGVuZ3RoID09IDApIHtcbiAgICAgICAgZGVsZXRlIHVzZXIuYXV0aERhdGE7XG4gICAgICB9XG4gICAgfVxuICB9XG59O1xuXG5SZXN0V3JpdGUucHJvdG90eXBlLl91cGRhdGVSZXNwb25zZVdpdGhEYXRhID0gZnVuY3Rpb24gKHJlc3BvbnNlLCBkYXRhKSB7XG4gIGlmIChfLmlzRW1wdHkodGhpcy5zdG9yYWdlLmZpZWxkc0NoYW5nZWRCeVRyaWdnZXIpKSB7XG4gICAgcmV0dXJuIHJlc3BvbnNlO1xuICB9XG4gIGNvbnN0IGNsaWVudFN1cHBvcnRzRGVsZXRlID0gQ2xpZW50U0RLLnN1cHBvcnRzRm9yd2FyZERlbGV0ZSh0aGlzLmNsaWVudFNESyk7XG4gIHRoaXMuc3RvcmFnZS5maWVsZHNDaGFuZ2VkQnlUcmlnZ2VyLmZvckVhY2goZmllbGROYW1lID0+IHtcbiAgICBjb25zdCBkYXRhVmFsdWUgPSBkYXRhW2ZpZWxkTmFtZV07XG5cbiAgICBpZiAoIU9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChyZXNwb25zZSwgZmllbGROYW1lKSkge1xuICAgICAgcmVzcG9uc2VbZmllbGROYW1lXSA9IGRhdGFWYWx1ZTtcbiAgICB9XG5cbiAgICAvLyBTdHJpcHMgb3BlcmF0aW9ucyBmcm9tIHJlc3BvbnNlc1xuICAgIGlmIChyZXNwb25zZVtmaWVsZE5hbWVdICYmIHJlc3BvbnNlW2ZpZWxkTmFtZV0uX19vcCkge1xuICAgICAgZGVsZXRlIHJlc3BvbnNlW2ZpZWxkTmFtZV07XG4gICAgICBpZiAoY2xpZW50U3VwcG9ydHNEZWxldGUgJiYgZGF0YVZhbHVlLl9fb3AgPT0gJ0RlbGV0ZScpIHtcbiAgICAgICAgcmVzcG9uc2VbZmllbGROYW1lXSA9IGRhdGFWYWx1ZTtcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xuICByZXR1cm4gcmVzcG9uc2U7XG59O1xuXG5leHBvcnQgZGVmYXVsdCBSZXN0V3JpdGU7XG5tb2R1bGUuZXhwb3J0cyA9IFJlc3RXcml0ZTtcbiJdfQ==