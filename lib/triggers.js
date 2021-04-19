"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.addFunction = addFunction;
exports.addJob = addJob;
exports.addTrigger = addTrigger;
exports.addFileTrigger = addFileTrigger;
exports.addConnectTrigger = addConnectTrigger;
exports.addLiveQueryEventHandler = addLiveQueryEventHandler;
exports.removeFunction = removeFunction;
exports.removeTrigger = removeTrigger;
exports._unregisterAll = _unregisterAll;
exports.getTrigger = getTrigger;
exports.runTrigger = runTrigger;
exports.getFileTrigger = getFileTrigger;
exports.triggerExists = triggerExists;
exports.getFunction = getFunction;
exports.getFunctionNames = getFunctionNames;
exports.getJob = getJob;
exports.getJobs = getJobs;
exports.getValidator = getValidator;
exports.getRequestObject = getRequestObject;
exports.getRequestQueryObject = getRequestQueryObject;
exports.getResponseObject = getResponseObject;
exports.maybeRunAfterFindTrigger = maybeRunAfterFindTrigger;
exports.maybeRunQueryTrigger = maybeRunQueryTrigger;
exports.resolveError = resolveError;
exports.maybeRunValidator = maybeRunValidator;
exports.maybeRunTrigger = maybeRunTrigger;
exports.inflate = inflate;
exports.runLiveQueryEventHandlers = runLiveQueryEventHandlers;
exports.getRequestFileObject = getRequestFileObject;
exports.maybeRunFileTrigger = maybeRunFileTrigger;
exports.Types = void 0;

var _node = _interopRequireDefault(require("parse/node"));

var _logger = require("./logger");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

const Types = {
  beforeLogin: 'beforeLogin',
  afterLogin: 'afterLogin',
  afterLogout: 'afterLogout',
  beforeSave: 'beforeSave',
  afterSave: 'afterSave',
  beforeDelete: 'beforeDelete',
  afterDelete: 'afterDelete',
  beforeFind: 'beforeFind',
  afterFind: 'afterFind',
  beforeSaveFile: 'beforeSaveFile',
  afterSaveFile: 'afterSaveFile',
  beforeDeleteFile: 'beforeDeleteFile',
  afterDeleteFile: 'afterDeleteFile',
  beforeConnect: 'beforeConnect',
  beforeSubscribe: 'beforeSubscribe',
  afterEvent: 'afterEvent'
};
exports.Types = Types;
const FileClassName = '@File';
const ConnectClassName = '@Connect';

const baseStore = function () {
  const Validators = Object.keys(Types).reduce(function (base, key) {
    base[key] = {};
    return base;
  }, {});
  const Functions = {};
  const Jobs = {};
  const LiveQuery = [];
  const Triggers = Object.keys(Types).reduce(function (base, key) {
    base[key] = {};
    return base;
  }, {});
  return Object.freeze({
    Functions,
    Jobs,
    Validators,
    Triggers,
    LiveQuery
  });
};

function validateClassNameForTriggers(className, type) {
  if (type == Types.beforeSave && className === '_PushStatus') {
    // _PushStatus uses undocumented nested key increment ops
    // allowing beforeSave would mess up the objects big time
    // TODO: Allow proper documented way of using nested increment ops
    throw 'Only afterSave is allowed on _PushStatus';
  }

  if ((type === Types.beforeLogin || type === Types.afterLogin) && className !== '_User') {
    // TODO: check if upstream code will handle `Error` instance rather
    // than this anti-pattern of throwing strings
    throw 'Only the _User class is allowed for the beforeLogin and afterLogin triggers';
  }

  if (type === Types.afterLogout && className !== '_Session') {
    // TODO: check if upstream code will handle `Error` instance rather
    // than this anti-pattern of throwing strings
    throw 'Only the _Session class is allowed for the afterLogout trigger.';
  }

  if (className === '_Session' && type !== Types.afterLogout) {
    // TODO: check if upstream code will handle `Error` instance rather
    // than this anti-pattern of throwing strings
    throw 'Only the afterLogout trigger is allowed for the _Session class.';
  }

  return className;
}

const _triggerStore = {};
const Category = {
  Functions: 'Functions',
  Validators: 'Validators',
  Jobs: 'Jobs',
  Triggers: 'Triggers'
};

function getStore(category, name, applicationId) {
  const path = name.split('.');
  path.splice(-1); // remove last component

  applicationId = applicationId || _node.default.applicationId;
  _triggerStore[applicationId] = _triggerStore[applicationId] || baseStore();
  let store = _triggerStore[applicationId][category];

  for (const component of path) {
    store = store[component];

    if (!store) {
      return undefined;
    }
  }

  return store;
}

function add(category, name, handler, applicationId) {
  const lastComponent = name.split('.').splice(-1);
  const store = getStore(category, name, applicationId);

  if (store[lastComponent]) {
    _logger.logger.warn(`Warning: Duplicate cloud functions exist for ${lastComponent}. Only the last one will be used and the others will be ignored.`);
  }

  store[lastComponent] = handler;
}

function remove(category, name, applicationId) {
  const lastComponent = name.split('.').splice(-1);
  const store = getStore(category, name, applicationId);
  delete store[lastComponent];
}

function get(category, name, applicationId) {
  const lastComponent = name.split('.').splice(-1);
  const store = getStore(category, name, applicationId);
  return store[lastComponent];
}

function addFunction(functionName, handler, validationHandler, applicationId) {
  add(Category.Functions, functionName, handler, applicationId);
  add(Category.Validators, functionName, validationHandler, applicationId);
}

function addJob(jobName, handler, applicationId) {
  add(Category.Jobs, jobName, handler, applicationId);
}

function addTrigger(type, className, handler, applicationId, validationHandler) {
  validateClassNameForTriggers(className, type);
  add(Category.Triggers, `${type}.${className}`, handler, applicationId);
  add(Category.Validators, `${type}.${className}`, validationHandler, applicationId);
}

function addFileTrigger(type, handler, applicationId, validationHandler) {
  add(Category.Triggers, `${type}.${FileClassName}`, handler, applicationId);
  add(Category.Validators, `${type}.${FileClassName}`, validationHandler, applicationId);
}

function addConnectTrigger(type, handler, applicationId, validationHandler) {
  add(Category.Triggers, `${type}.${ConnectClassName}`, handler, applicationId);
  add(Category.Validators, `${type}.${ConnectClassName}`, validationHandler, applicationId);
}

function addLiveQueryEventHandler(handler, applicationId) {
  applicationId = applicationId || _node.default.applicationId;
  _triggerStore[applicationId] = _triggerStore[applicationId] || baseStore();

  _triggerStore[applicationId].LiveQuery.push(handler);
}

function removeFunction(functionName, applicationId) {
  remove(Category.Functions, functionName, applicationId);
}

function removeTrigger(type, className, applicationId) {
  remove(Category.Triggers, `${type}.${className}`, applicationId);
}

function _unregisterAll() {
  Object.keys(_triggerStore).forEach(appId => delete _triggerStore[appId]);
}

function getTrigger(className, triggerType, applicationId) {
  if (!applicationId) {
    throw 'Missing ApplicationID';
  }

  return get(Category.Triggers, `${triggerType}.${className}`, applicationId);
}

async function runTrigger(trigger, name, request, auth) {
  if (!trigger) {
    return;
  }

  await maybeRunValidator(request, name, auth);

  if (request.skipWithMasterKey) {
    return;
  }

  return await trigger(request);
}

function getFileTrigger(type, applicationId) {
  return getTrigger(FileClassName, type, applicationId);
}

function triggerExists(className, type, applicationId) {
  return getTrigger(className, type, applicationId) != undefined;
}

function getFunction(functionName, applicationId) {
  return get(Category.Functions, functionName, applicationId);
}

function getFunctionNames(applicationId) {
  const store = _triggerStore[applicationId] && _triggerStore[applicationId][Category.Functions] || {};
  const functionNames = [];

  const extractFunctionNames = (namespace, store) => {
    Object.keys(store).forEach(name => {
      const value = store[name];

      if (namespace) {
        name = `${namespace}.${name}`;
      }

      if (typeof value === 'function') {
        functionNames.push(name);
      } else {
        extractFunctionNames(name, value);
      }
    });
  };

  extractFunctionNames(null, store);
  return functionNames;
}

function getJob(jobName, applicationId) {
  return get(Category.Jobs, jobName, applicationId);
}

function getJobs(applicationId) {
  var manager = _triggerStore[applicationId];

  if (manager && manager.Jobs) {
    return manager.Jobs;
  }

  return undefined;
}

function getValidator(functionName, applicationId) {
  return get(Category.Validators, functionName, applicationId);
}

function getRequestObject(triggerType, auth, parseObject, originalParseObject, config, context) {
  const request = {
    triggerName: triggerType,
    object: parseObject,
    master: false,
    log: config.loggerController,
    headers: config.headers,
    ip: config.ip
  };

  if (originalParseObject) {
    request.original = originalParseObject;
  }

  if (triggerType === Types.beforeSave || triggerType === Types.afterSave || triggerType === Types.beforeDelete || triggerType === Types.afterDelete || triggerType === Types.afterFind) {
    // Set a copy of the context on the request object.
    request.context = Object.assign({}, context);
  }

  if (!auth) {
    return request;
  }

  if (auth.isMaster) {
    request['master'] = true;
  }

  if (auth.user) {
    request['user'] = auth.user;
  }

  if (auth.installationId) {
    request['installationId'] = auth.installationId;
  }

  return request;
}

function getRequestQueryObject(triggerType, auth, query, count, config, context, isGet) {
  isGet = !!isGet;
  var request = {
    triggerName: triggerType,
    query,
    master: false,
    count,
    log: config.loggerController,
    isGet,
    headers: config.headers,
    ip: config.ip,
    context: context || {}
  };

  if (!auth) {
    return request;
  }

  if (auth.isMaster) {
    request['master'] = true;
  }

  if (auth.user) {
    request['user'] = auth.user;
  }

  if (auth.installationId) {
    request['installationId'] = auth.installationId;
  }

  return request;
} // Creates the response object, and uses the request object to pass data
// The API will call this with REST API formatted objects, this will
// transform them to Parse.Object instances expected by Cloud Code.
// Any changes made to the object in a beforeSave will be included.


function getResponseObject(request, resolve, reject) {
  return {
    success: function (response) {
      if (request.triggerName === Types.afterFind) {
        if (!response) {
          response = request.objects;
        }

        response = response.map(object => {
          return object.toJSON();
        });
        return resolve(response);
      } // Use the JSON response


      if (response && typeof response === 'object' && !request.object.equals(response) && request.triggerName === Types.beforeSave) {
        return resolve(response);
      }

      if (response && typeof response === 'object' && request.triggerName === Types.afterSave) {
        return resolve(response);
      }

      if (request.triggerName === Types.afterSave) {
        return resolve();
      }

      response = {};

      if (request.triggerName === Types.beforeSave) {
        response['object'] = request.object._getSaveJSON();
        response['object']['objectId'] = request.object.id;
      }

      return resolve(response);
    },
    error: function (error) {
      const e = resolveError(error, {
        code: _node.default.Error.SCRIPT_FAILED,
        message: 'Script failed. Unknown error.'
      });
      reject(e);
    }
  };
}

function userIdForLog(auth) {
  return auth && auth.user ? auth.user.id : undefined;
}

function logTriggerAfterHook(triggerType, className, input, auth) {
  const cleanInput = _logger.logger.truncateLogMessage(JSON.stringify(input));

  _logger.logger.info(`${triggerType} triggered for ${className} for user ${userIdForLog(auth)}:\n  Input: ${cleanInput}`, {
    className,
    triggerType,
    user: userIdForLog(auth)
  });
}

function logTriggerSuccessBeforeHook(triggerType, className, input, result, auth) {
  const cleanInput = _logger.logger.truncateLogMessage(JSON.stringify(input));

  const cleanResult = _logger.logger.truncateLogMessage(JSON.stringify(result));

  _logger.logger.info(`${triggerType} triggered for ${className} for user ${userIdForLog(auth)}:\n  Input: ${cleanInput}\n  Result: ${cleanResult}`, {
    className,
    triggerType,
    user: userIdForLog(auth)
  });
}

function logTriggerErrorBeforeHook(triggerType, className, input, auth, error) {
  const cleanInput = _logger.logger.truncateLogMessage(JSON.stringify(input));

  _logger.logger.error(`${triggerType} failed for ${className} for user ${userIdForLog(auth)}:\n  Input: ${cleanInput}\n  Error: ${JSON.stringify(error)}`, {
    className,
    triggerType,
    error,
    user: userIdForLog(auth)
  });
}

function maybeRunAfterFindTrigger(triggerType, auth, className, objects, config, query, context) {
  return new Promise((resolve, reject) => {
    const trigger = getTrigger(className, triggerType, config.applicationId);

    if (!trigger) {
      return resolve();
    }

    const request = getRequestObject(triggerType, auth, null, null, config, context);

    if (query) {
      request.query = query;
    }

    const {
      success,
      error
    } = getResponseObject(request, object => {
      resolve(object);
    }, error => {
      reject(error);
    });
    logTriggerSuccessBeforeHook(triggerType, className, 'AfterFind', JSON.stringify(objects), auth);
    request.objects = objects.map(object => {
      //setting the class name to transform into parse object
      object.className = className;
      return _node.default.Object.fromJSON(object);
    });
    return Promise.resolve().then(() => {
      return maybeRunValidator(request, `${triggerType}.${className}`, auth);
    }).then(() => {
      if (request.skipWithMasterKey) {
        return request.objects;
      }

      const response = trigger(request);

      if (response && typeof response.then === 'function') {
        return response.then(results => {
          if (!results) {
            throw new _node.default.Error(_node.default.Error.SCRIPT_FAILED, 'AfterFind expect results to be returned in the promise');
          }

          return results;
        });
      }

      return response;
    }).then(success, error);
  }).then(results => {
    logTriggerAfterHook(triggerType, className, JSON.stringify(results), auth);
    return results;
  });
}

function maybeRunQueryTrigger(triggerType, className, restWhere, restOptions, config, auth, context, isGet) {
  const trigger = getTrigger(className, triggerType, config.applicationId);

  if (!trigger) {
    return Promise.resolve({
      restWhere,
      restOptions
    });
  }

  const json = Object.assign({}, restOptions);
  json.where = restWhere;
  const parseQuery = new _node.default.Query(className);
  parseQuery.withJSON(json);
  let count = false;

  if (restOptions) {
    count = !!restOptions.count;
  }

  const requestObject = getRequestQueryObject(triggerType, auth, parseQuery, count, config, context, isGet);
  return Promise.resolve().then(() => {
    return maybeRunValidator(requestObject, `${triggerType}.${className}`, auth);
  }).then(() => {
    if (requestObject.skipWithMasterKey) {
      return requestObject.query;
    }

    return trigger(requestObject);
  }).then(result => {
    let queryResult = parseQuery;

    if (result && result instanceof _node.default.Query) {
      queryResult = result;
    }

    const jsonQuery = queryResult.toJSON();

    if (jsonQuery.where) {
      restWhere = jsonQuery.where;
    }

    if (jsonQuery.limit) {
      restOptions = restOptions || {};
      restOptions.limit = jsonQuery.limit;
    }

    if (jsonQuery.skip) {
      restOptions = restOptions || {};
      restOptions.skip = jsonQuery.skip;
    }

    if (jsonQuery.include) {
      restOptions = restOptions || {};
      restOptions.include = jsonQuery.include;
    }

    if (jsonQuery.excludeKeys) {
      restOptions = restOptions || {};
      restOptions.excludeKeys = jsonQuery.excludeKeys;
    }

    if (jsonQuery.explain) {
      restOptions = restOptions || {};
      restOptions.explain = jsonQuery.explain;
    }

    if (jsonQuery.keys) {
      restOptions = restOptions || {};
      restOptions.keys = jsonQuery.keys;
    }

    if (jsonQuery.order) {
      restOptions = restOptions || {};
      restOptions.order = jsonQuery.order;
    }

    if (jsonQuery.hint) {
      restOptions = restOptions || {};
      restOptions.hint = jsonQuery.hint;
    }

    if (requestObject.readPreference) {
      restOptions = restOptions || {};
      restOptions.readPreference = requestObject.readPreference;
    }

    if (requestObject.includeReadPreference) {
      restOptions = restOptions || {};
      restOptions.includeReadPreference = requestObject.includeReadPreference;
    }

    if (requestObject.subqueryReadPreference) {
      restOptions = restOptions || {};
      restOptions.subqueryReadPreference = requestObject.subqueryReadPreference;
    }

    return {
      restWhere,
      restOptions
    };
  }, err => {
    const error = resolveError(err, {
      code: _node.default.Error.SCRIPT_FAILED,
      message: 'Script failed. Unknown error.'
    });
    throw error;
  });
}

function resolveError(message, defaultOpts) {
  if (!defaultOpts) {
    defaultOpts = {};
  }

  if (!message) {
    return new _node.default.Error(defaultOpts.code || _node.default.Error.SCRIPT_FAILED, defaultOpts.message || 'Script failed.');
  }

  if (message instanceof _node.default.Error) {
    return message;
  }

  const code = defaultOpts.code || _node.default.Error.SCRIPT_FAILED; // If it's an error, mark it as a script failed

  if (typeof message === 'string') {
    return new _node.default.Error(code, message);
  }

  const error = new _node.default.Error(code, message.message || message);

  if (message instanceof Error) {
    error.stack = message.stack;
  }

  return error;
}

function maybeRunValidator(request, functionName, auth) {
  const theValidator = getValidator(functionName, _node.default.applicationId);

  if (!theValidator) {
    return;
  }

  if (typeof theValidator === 'object' && theValidator.skipWithMasterKey && request.master) {
    request.skipWithMasterKey = true;
  }

  return new Promise((resolve, reject) => {
    return Promise.resolve().then(() => {
      return typeof theValidator === 'object' ? builtInTriggerValidator(theValidator, request, auth) : theValidator(request);
    }).then(() => {
      resolve();
    }).catch(e => {
      const error = resolveError(e, {
        code: _node.default.Error.VALIDATION_ERROR,
        message: 'Validation failed.'
      });
      reject(error);
    });
  });
}

async function builtInTriggerValidator(options, request, auth) {
  if (request.master && !options.validateMasterKey) {
    return;
  }

  let reqUser = request.user;

  if (!reqUser && request.object && request.object.className === '_User' && !request.object.existed()) {
    reqUser = request.object;
  }

  if ((options.requireUser || options.requireAnyUserRoles || options.requireAllUserRoles) && !reqUser) {
    throw 'Validation failed. Please login to continue.';
  }

  if (options.requireMaster && !request.master) {
    throw 'Validation failed. Master key is required to complete this request.';
  }

  let params = request.params || {};

  if (request.object) {
    params = request.object.toJSON();
  }

  const requiredParam = key => {
    const value = params[key];

    if (value == null) {
      throw `Validation failed. Please specify data for ${key}.`;
    }
  };

  const validateOptions = async (opt, key, val) => {
    let opts = opt.options;

    if (typeof opts === 'function') {
      try {
        const result = await opts(val);

        if (!result && result != null) {
          throw opt.error || `Validation failed. Invalid value for ${key}.`;
        }
      } catch (e) {
        if (!e) {
          throw opt.error || `Validation failed. Invalid value for ${key}.`;
        }

        throw opt.error || e.message || e;
      }

      return;
    }

    if (!Array.isArray(opts)) {
      opts = [opt.options];
    }

    if (!opts.includes(val)) {
      throw opt.error || `Validation failed. Invalid option for ${key}. Expected: ${opts.join(', ')}`;
    }
  };

  const getType = fn => {
    const match = fn && fn.toString().match(/^\s*function (\w+)/);
    return (match ? match[1] : '').toLowerCase();
  };

  if (Array.isArray(options.fields)) {
    for (const key of options.fields) {
      requiredParam(key);
    }
  } else {
    const optionPromises = [];

    for (const key in options.fields) {
      const opt = options.fields[key];
      let val = params[key];

      if (typeof opt === 'string') {
        requiredParam(opt);
      }

      if (typeof opt === 'object') {
        if (opt.default != null && val == null) {
          val = opt.default;
          params[key] = val;

          if (request.object) {
            request.object.set(key, val);
          }
        }

        if (opt.constant && request.object) {
          if (request.original) {
            request.object.set(key, request.original.get(key));
          } else if (opt.default != null) {
            request.object.set(key, opt.default);
          }
        }

        if (opt.required) {
          requiredParam(key);
        }

        const optional = !opt.required && val === undefined;

        if (!optional) {
          if (opt.type) {
            const type = getType(opt.type);
            const valType = Array.isArray(val) ? 'array' : typeof val;

            if (valType !== type) {
              throw `Validation failed. Invalid type for ${key}. Expected: ${type}`;
            }
          }

          if (opt.options) {
            optionPromises.push(validateOptions(opt, key, val));
          }
        }
      }
    }

    await Promise.all(optionPromises);
  }

  let userRoles = options.requireAnyUserRoles;
  let requireAllRoles = options.requireAllUserRoles;
  const promises = [Promise.resolve(), Promise.resolve(), Promise.resolve()];

  if (userRoles || requireAllRoles) {
    promises[0] = auth.getUserRoles();
  }

  if (typeof userRoles === 'function') {
    promises[1] = userRoles();
  }

  if (typeof requireAllRoles === 'function') {
    promises[2] = requireAllRoles();
  }

  const [roles, resolvedUserRoles, resolvedRequireAll] = await Promise.all(promises);

  if (resolvedUserRoles && Array.isArray(resolvedUserRoles)) {
    userRoles = resolvedUserRoles;
  }

  if (resolvedRequireAll && Array.isArray(resolvedRequireAll)) {
    requireAllRoles = resolvedRequireAll;
  }

  if (userRoles) {
    const hasRole = userRoles.some(requiredRole => roles.includes(`role:${requiredRole}`));

    if (!hasRole) {
      throw `Validation failed. User does not match the required roles.`;
    }
  }

  if (requireAllRoles) {
    for (const requiredRole of requireAllRoles) {
      if (!roles.includes(`role:${requiredRole}`)) {
        throw `Validation failed. User does not match all the required roles.`;
      }
    }
  }

  const userKeys = options.requireUserKeys || [];

  if (Array.isArray(userKeys)) {
    for (const key of userKeys) {
      if (!reqUser) {
        throw 'Please login to make this request.';
      }

      if (reqUser.get(key) == null) {
        throw `Validation failed. Please set data for ${key} on your account.`;
      }
    }
  } else if (typeof userKeys === 'object') {
    const optionPromises = [];

    for (const key in options.requireUserKeys) {
      const opt = options.requireUserKeys[key];

      if (opt.options) {
        optionPromises.push(validateOptions(opt, key, reqUser.get(key)));
      }
    }

    await Promise.all(optionPromises);
  }
} // To be used as part of the promise chain when saving/deleting an object
// Will resolve successfully if no trigger is configured
// Resolves to an object, empty or containing an object key. A beforeSave
// trigger will set the object key to the rest format object to save.
// originalParseObject is optional, we only need that for before/afterSave functions


function maybeRunTrigger(triggerType, auth, parseObject, originalParseObject, config, context) {
  if (!parseObject) {
    return Promise.resolve({});
  }

  return new Promise(function (resolve, reject) {
    var trigger = getTrigger(parseObject.className, triggerType, config.applicationId);
    if (!trigger) return resolve();
    var request = getRequestObject(triggerType, auth, parseObject, originalParseObject, config, context);
    var {
      success,
      error
    } = getResponseObject(request, object => {
      logTriggerSuccessBeforeHook(triggerType, parseObject.className, parseObject.toJSON(), object, auth);

      if (triggerType === Types.beforeSave || triggerType === Types.afterSave || triggerType === Types.beforeDelete || triggerType === Types.afterDelete) {
        Object.assign(context, request.context);
      }

      resolve(object);
    }, error => {
      logTriggerErrorBeforeHook(triggerType, parseObject.className, parseObject.toJSON(), auth, error);
      reject(error);
    }); // AfterSave and afterDelete triggers can return a promise, which if they
    // do, needs to be resolved before this promise is resolved,
    // so trigger execution is synced with RestWrite.execute() call.
    // If triggers do not return a promise, they can run async code parallel
    // to the RestWrite.execute() call.

    return Promise.resolve().then(() => {
      return maybeRunValidator(request, `${triggerType}.${parseObject.className}`, auth);
    }).then(() => {
      if (request.skipWithMasterKey) {
        return Promise.resolve();
      }

      const promise = trigger(request);

      if (triggerType === Types.afterSave || triggerType === Types.afterDelete || triggerType === Types.afterLogin) {
        logTriggerAfterHook(triggerType, parseObject.className, parseObject.toJSON(), auth);
      } // beforeSave is expected to return null (nothing)


      if (triggerType === Types.beforeSave) {
        if (promise && typeof promise.then === 'function') {
          return promise.then(response => {
            // response.object may come from express routing before hook
            if (response && response.object) {
              return response;
            }

            return null;
          });
        }

        return null;
      }

      return promise;
    }).then(success, error);
  });
} // Converts a REST-format object to a Parse.Object
// data is either className or an object


function inflate(data, restObject) {
  var copy = typeof data == 'object' ? data : {
    className: data
  };

  for (var key in restObject) {
    copy[key] = restObject[key];
  }

  return _node.default.Object.fromJSON(copy);
}

function runLiveQueryEventHandlers(data, applicationId = _node.default.applicationId) {
  if (!_triggerStore || !_triggerStore[applicationId] || !_triggerStore[applicationId].LiveQuery) {
    return;
  }

  _triggerStore[applicationId].LiveQuery.forEach(handler => handler(data));
}

function getRequestFileObject(triggerType, auth, fileObject, config) {
  const request = _objectSpread(_objectSpread({}, fileObject), {}, {
    triggerName: triggerType,
    master: false,
    log: config.loggerController,
    headers: config.headers,
    ip: config.ip
  });

  if (!auth) {
    return request;
  }

  if (auth.isMaster) {
    request['master'] = true;
  }

  if (auth.user) {
    request['user'] = auth.user;
  }

  if (auth.installationId) {
    request['installationId'] = auth.installationId;
  }

  return request;
}

async function maybeRunFileTrigger(triggerType, fileObject, config, auth) {
  const fileTrigger = getFileTrigger(triggerType, config.applicationId);

  if (typeof fileTrigger === 'function') {
    try {
      const request = getRequestFileObject(triggerType, auth, fileObject, config);
      await maybeRunValidator(request, `${triggerType}.${FileClassName}`, auth);

      if (request.skipWithMasterKey) {
        return fileObject;
      }

      const result = await fileTrigger(request);
      logTriggerSuccessBeforeHook(triggerType, 'Parse.File', _objectSpread(_objectSpread({}, fileObject.file.toJSON()), {}, {
        fileSize: fileObject.fileSize
      }), result, auth);
      return result || fileObject;
    } catch (error) {
      logTriggerErrorBeforeHook(triggerType, 'Parse.File', _objectSpread(_objectSpread({}, fileObject.file.toJSON()), {}, {
        fileSize: fileObject.fileSize
      }), auth, error);
      throw error;
    }
  }

  return fileObject;
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy90cmlnZ2Vycy5qcyJdLCJuYW1lcyI6WyJUeXBlcyIsImJlZm9yZUxvZ2luIiwiYWZ0ZXJMb2dpbiIsImFmdGVyTG9nb3V0IiwiYmVmb3JlU2F2ZSIsImFmdGVyU2F2ZSIsImJlZm9yZURlbGV0ZSIsImFmdGVyRGVsZXRlIiwiYmVmb3JlRmluZCIsImFmdGVyRmluZCIsImJlZm9yZVNhdmVGaWxlIiwiYWZ0ZXJTYXZlRmlsZSIsImJlZm9yZURlbGV0ZUZpbGUiLCJhZnRlckRlbGV0ZUZpbGUiLCJiZWZvcmVDb25uZWN0IiwiYmVmb3JlU3Vic2NyaWJlIiwiYWZ0ZXJFdmVudCIsIkZpbGVDbGFzc05hbWUiLCJDb25uZWN0Q2xhc3NOYW1lIiwiYmFzZVN0b3JlIiwiVmFsaWRhdG9ycyIsIk9iamVjdCIsImtleXMiLCJyZWR1Y2UiLCJiYXNlIiwia2V5IiwiRnVuY3Rpb25zIiwiSm9icyIsIkxpdmVRdWVyeSIsIlRyaWdnZXJzIiwiZnJlZXplIiwidmFsaWRhdGVDbGFzc05hbWVGb3JUcmlnZ2VycyIsImNsYXNzTmFtZSIsInR5cGUiLCJfdHJpZ2dlclN0b3JlIiwiQ2F0ZWdvcnkiLCJnZXRTdG9yZSIsImNhdGVnb3J5IiwibmFtZSIsImFwcGxpY2F0aW9uSWQiLCJwYXRoIiwic3BsaXQiLCJzcGxpY2UiLCJQYXJzZSIsInN0b3JlIiwiY29tcG9uZW50IiwidW5kZWZpbmVkIiwiYWRkIiwiaGFuZGxlciIsImxhc3RDb21wb25lbnQiLCJsb2dnZXIiLCJ3YXJuIiwicmVtb3ZlIiwiZ2V0IiwiYWRkRnVuY3Rpb24iLCJmdW5jdGlvbk5hbWUiLCJ2YWxpZGF0aW9uSGFuZGxlciIsImFkZEpvYiIsImpvYk5hbWUiLCJhZGRUcmlnZ2VyIiwiYWRkRmlsZVRyaWdnZXIiLCJhZGRDb25uZWN0VHJpZ2dlciIsImFkZExpdmVRdWVyeUV2ZW50SGFuZGxlciIsInB1c2giLCJyZW1vdmVGdW5jdGlvbiIsInJlbW92ZVRyaWdnZXIiLCJfdW5yZWdpc3RlckFsbCIsImZvckVhY2giLCJhcHBJZCIsImdldFRyaWdnZXIiLCJ0cmlnZ2VyVHlwZSIsInJ1blRyaWdnZXIiLCJ0cmlnZ2VyIiwicmVxdWVzdCIsImF1dGgiLCJtYXliZVJ1blZhbGlkYXRvciIsInNraXBXaXRoTWFzdGVyS2V5IiwiZ2V0RmlsZVRyaWdnZXIiLCJ0cmlnZ2VyRXhpc3RzIiwiZ2V0RnVuY3Rpb24iLCJnZXRGdW5jdGlvbk5hbWVzIiwiZnVuY3Rpb25OYW1lcyIsImV4dHJhY3RGdW5jdGlvbk5hbWVzIiwibmFtZXNwYWNlIiwidmFsdWUiLCJnZXRKb2IiLCJnZXRKb2JzIiwibWFuYWdlciIsImdldFZhbGlkYXRvciIsImdldFJlcXVlc3RPYmplY3QiLCJwYXJzZU9iamVjdCIsIm9yaWdpbmFsUGFyc2VPYmplY3QiLCJjb25maWciLCJjb250ZXh0IiwidHJpZ2dlck5hbWUiLCJvYmplY3QiLCJtYXN0ZXIiLCJsb2ciLCJsb2dnZXJDb250cm9sbGVyIiwiaGVhZGVycyIsImlwIiwib3JpZ2luYWwiLCJhc3NpZ24iLCJpc01hc3RlciIsInVzZXIiLCJpbnN0YWxsYXRpb25JZCIsImdldFJlcXVlc3RRdWVyeU9iamVjdCIsInF1ZXJ5IiwiY291bnQiLCJpc0dldCIsImdldFJlc3BvbnNlT2JqZWN0IiwicmVzb2x2ZSIsInJlamVjdCIsInN1Y2Nlc3MiLCJyZXNwb25zZSIsIm9iamVjdHMiLCJtYXAiLCJ0b0pTT04iLCJlcXVhbHMiLCJfZ2V0U2F2ZUpTT04iLCJpZCIsImVycm9yIiwiZSIsInJlc29sdmVFcnJvciIsImNvZGUiLCJFcnJvciIsIlNDUklQVF9GQUlMRUQiLCJtZXNzYWdlIiwidXNlcklkRm9yTG9nIiwibG9nVHJpZ2dlckFmdGVySG9vayIsImlucHV0IiwiY2xlYW5JbnB1dCIsInRydW5jYXRlTG9nTWVzc2FnZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJpbmZvIiwibG9nVHJpZ2dlclN1Y2Nlc3NCZWZvcmVIb29rIiwicmVzdWx0IiwiY2xlYW5SZXN1bHQiLCJsb2dUcmlnZ2VyRXJyb3JCZWZvcmVIb29rIiwibWF5YmVSdW5BZnRlckZpbmRUcmlnZ2VyIiwiUHJvbWlzZSIsImZyb21KU09OIiwidGhlbiIsInJlc3VsdHMiLCJtYXliZVJ1blF1ZXJ5VHJpZ2dlciIsInJlc3RXaGVyZSIsInJlc3RPcHRpb25zIiwianNvbiIsIndoZXJlIiwicGFyc2VRdWVyeSIsIlF1ZXJ5Iiwid2l0aEpTT04iLCJyZXF1ZXN0T2JqZWN0IiwicXVlcnlSZXN1bHQiLCJqc29uUXVlcnkiLCJsaW1pdCIsInNraXAiLCJpbmNsdWRlIiwiZXhjbHVkZUtleXMiLCJleHBsYWluIiwib3JkZXIiLCJoaW50IiwicmVhZFByZWZlcmVuY2UiLCJpbmNsdWRlUmVhZFByZWZlcmVuY2UiLCJzdWJxdWVyeVJlYWRQcmVmZXJlbmNlIiwiZXJyIiwiZGVmYXVsdE9wdHMiLCJzdGFjayIsInRoZVZhbGlkYXRvciIsImJ1aWx0SW5UcmlnZ2VyVmFsaWRhdG9yIiwiY2F0Y2giLCJWQUxJREFUSU9OX0VSUk9SIiwib3B0aW9ucyIsInZhbGlkYXRlTWFzdGVyS2V5IiwicmVxVXNlciIsImV4aXN0ZWQiLCJyZXF1aXJlVXNlciIsInJlcXVpcmVBbnlVc2VyUm9sZXMiLCJyZXF1aXJlQWxsVXNlclJvbGVzIiwicmVxdWlyZU1hc3RlciIsInBhcmFtcyIsInJlcXVpcmVkUGFyYW0iLCJ2YWxpZGF0ZU9wdGlvbnMiLCJvcHQiLCJ2YWwiLCJvcHRzIiwiQXJyYXkiLCJpc0FycmF5IiwiaW5jbHVkZXMiLCJqb2luIiwiZ2V0VHlwZSIsImZuIiwibWF0Y2giLCJ0b1N0cmluZyIsInRvTG93ZXJDYXNlIiwiZmllbGRzIiwib3B0aW9uUHJvbWlzZXMiLCJkZWZhdWx0Iiwic2V0IiwiY29uc3RhbnQiLCJyZXF1aXJlZCIsIm9wdGlvbmFsIiwidmFsVHlwZSIsImFsbCIsInVzZXJSb2xlcyIsInJlcXVpcmVBbGxSb2xlcyIsInByb21pc2VzIiwiZ2V0VXNlclJvbGVzIiwicm9sZXMiLCJyZXNvbHZlZFVzZXJSb2xlcyIsInJlc29sdmVkUmVxdWlyZUFsbCIsImhhc1JvbGUiLCJzb21lIiwicmVxdWlyZWRSb2xlIiwidXNlcktleXMiLCJyZXF1aXJlVXNlcktleXMiLCJtYXliZVJ1blRyaWdnZXIiLCJwcm9taXNlIiwiaW5mbGF0ZSIsImRhdGEiLCJyZXN0T2JqZWN0IiwiY29weSIsInJ1bkxpdmVRdWVyeUV2ZW50SGFuZGxlcnMiLCJnZXRSZXF1ZXN0RmlsZU9iamVjdCIsImZpbGVPYmplY3QiLCJtYXliZVJ1bkZpbGVUcmlnZ2VyIiwiZmlsZVRyaWdnZXIiLCJmaWxlIiwiZmlsZVNpemUiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFDQTs7QUFDQTs7Ozs7Ozs7OztBQUVPLE1BQU1BLEtBQUssR0FBRztBQUNuQkMsRUFBQUEsV0FBVyxFQUFFLGFBRE07QUFFbkJDLEVBQUFBLFVBQVUsRUFBRSxZQUZPO0FBR25CQyxFQUFBQSxXQUFXLEVBQUUsYUFITTtBQUluQkMsRUFBQUEsVUFBVSxFQUFFLFlBSk87QUFLbkJDLEVBQUFBLFNBQVMsRUFBRSxXQUxRO0FBTW5CQyxFQUFBQSxZQUFZLEVBQUUsY0FOSztBQU9uQkMsRUFBQUEsV0FBVyxFQUFFLGFBUE07QUFRbkJDLEVBQUFBLFVBQVUsRUFBRSxZQVJPO0FBU25CQyxFQUFBQSxTQUFTLEVBQUUsV0FUUTtBQVVuQkMsRUFBQUEsY0FBYyxFQUFFLGdCQVZHO0FBV25CQyxFQUFBQSxhQUFhLEVBQUUsZUFYSTtBQVluQkMsRUFBQUEsZ0JBQWdCLEVBQUUsa0JBWkM7QUFhbkJDLEVBQUFBLGVBQWUsRUFBRSxpQkFiRTtBQWNuQkMsRUFBQUEsYUFBYSxFQUFFLGVBZEk7QUFlbkJDLEVBQUFBLGVBQWUsRUFBRSxpQkFmRTtBQWdCbkJDLEVBQUFBLFVBQVUsRUFBRTtBQWhCTyxDQUFkOztBQW1CUCxNQUFNQyxhQUFhLEdBQUcsT0FBdEI7QUFDQSxNQUFNQyxnQkFBZ0IsR0FBRyxVQUF6Qjs7QUFFQSxNQUFNQyxTQUFTLEdBQUcsWUFBWTtBQUM1QixRQUFNQyxV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O0FBQ0EsWUFBTWpCLGlCQUFpQixDQUFDRixPQUFELEVBQVcsR0FBRUgsV0FBWSxJQUFHckQsYUFBYyxFQUExQyxFQUE2Q3lELElBQTdDLENBQXZCOztBQUNBLFVBQUlELE9BQU8sQ0FBQ0csaUJBQVosRUFBK0I7QUFDN0IsZUFBT3FKLFVBQVA7QUFDRDs7QUFDRCxZQUFNeEYsTUFBTSxHQUFHLE1BQU0wRixXQUFXLENBQUMxSixPQUFELENBQWhDO0FBQ0ErRCxNQUFBQSwyQkFBMkIsQ0FDekJsRSxXQUR5QixFQUV6QixZQUZ5QixrQ0FHcEIySixVQUFVLENBQUNHLElBQVgsQ0FBZ0IvRyxNQUFoQixFQUhvQjtBQUdNZ0gsUUFBQUEsUUFBUSxFQUFFSixVQUFVLENBQUNJO0FBSDNCLFVBSXpCNUYsTUFKeUIsRUFLekIvRCxJQUx5QixDQUEzQjtBQU9BLGFBQU8rRCxNQUFNLElBQUl3RixVQUFqQjtBQUNELEtBZkQsQ0FlRSxPQUFPeEcsS0FBUCxFQUFjO0FBQ2RrQixNQUFBQSx5QkFBeUIsQ0FDdkJyRSxXQUR1QixFQUV2QixZQUZ1QixrQ0FHbEIySixVQUFVLENBQUNHLElBQVgsQ0FBZ0IvRyxNQUFoQixFQUhrQjtBQUdRZ0gsUUFBQUEsUUFBUSxFQUFFSixVQUFVLENBQUNJO0FBSDdCLFVBSXZCM0osSUFKdUIsRUFLdkIrQyxLQUx1QixDQUF6QjtBQU9BLFlBQU1BLEtBQU47QUFDRDtBQUNGOztBQUNELFNBQU93RyxVQUFQO0FBQ0QiLCJzb3VyY2VzQ29udGVudCI6WyIvLyB0cmlnZ2Vycy5qc1xuaW1wb3J0IFBhcnNlIGZyb20gJ3BhcnNlL25vZGUnO1xuaW1wb3J0IHsgbG9nZ2VyIH0gZnJvbSAnLi9sb2dnZXInO1xuXG5leHBvcnQgY29uc3QgVHlwZXMgPSB7XG4gIGJlZm9yZUxvZ2luOiAnYmVmb3JlTG9naW4nLFxuICBhZnRlckxvZ2luOiAnYWZ0ZXJMb2dpbicsXG4gIGFmdGVyTG9nb3V0OiAnYWZ0ZXJMb2dvdXQnLFxuICBiZWZvcmVTYXZlOiAnYmVmb3JlU2F2ZScsXG4gIGFmdGVyU2F2ZTogJ2FmdGVyU2F2ZScsXG4gIGJlZm9yZURlbGV0ZTogJ2JlZm9yZURlbGV0ZScsXG4gIGFmdGVyRGVsZXRlOiAnYWZ0ZXJEZWxldGUnLFxuICBiZWZvcmVGaW5kOiAnYmVmb3JlRmluZCcsXG4gIGFmdGVyRmluZDogJ2FmdGVyRmluZCcsXG4gIGJlZm9yZVNhdmVGaWxlOiAnYmVmb3JlU2F2ZUZpbGUnLFxuICBhZnRlclNhdmVGaWxlOiAnYWZ0ZXJTYXZlRmlsZScsXG4gIGJlZm9yZURlbGV0ZUZpbGU6ICdiZWZvcmVEZWxldGVGaWxlJyxcbiAgYWZ0ZXJEZWxldGVGaWxlOiAnYWZ0ZXJEZWxldGVGaWxlJyxcbiAgYmVmb3JlQ29ubmVjdDogJ2JlZm9yZUNvbm5lY3QnLFxuICBiZWZvcmVTdWJzY3JpYmU6ICdiZWZvcmVTdWJzY3JpYmUnLFxuICBhZnRlckV2ZW50OiAnYWZ0ZXJFdmVudCcsXG59O1xuXG5jb25zdCBGaWxlQ2xhc3NOYW1lID0gJ0BGaWxlJztcbmNvbnN0IENvbm5lY3RDbGFzc05hbWUgPSAnQENvbm5lY3QnO1xuXG5jb25zdCBiYXNlU3RvcmUgPSBmdW5jdGlvbiAoKSB7XG4gIGNvbnN0IFZhbGlkYXRvcnMgPSBPYmplY3Qua2V5cyhUeXBlcykucmVkdWNlKGZ1bmN0aW9uIChiYXNlLCBrZXkpIHtcbiAgICBiYXNlW2tleV0gPSB7fTtcbiAgICByZXR1cm4gYmFzZTtcbiAgfSwge30pO1xuICBjb25zdCBGdW5jdGlvbnMgPSB7fTtcbiAgY29uc3QgSm9icyA9IHt9O1xuICBjb25zdCBMaXZlUXVlcnkgPSBbXTtcbiAgY29uc3QgVHJpZ2dlcnMgPSBPYmplY3Qua2V5cyhUeXBlcykucmVkdWNlKGZ1bmN0aW9uIChiYXNlLCBrZXkpIHtcbiAgICBiYXNlW2tleV0gPSB7fTtcbiAgICByZXR1cm4gYmFzZTtcbiAgfSwge30pO1xuXG4gIHJldHVybiBPYmplY3QuZnJlZXplKHtcbiAgICBGdW5jdGlvbnMsXG4gICAgSm9icyxcbiAgICBWYWxpZGF0b3JzLFxuICAgIFRyaWdnZXJzLFxuICAgIExpdmVRdWVyeSxcbiAgfSk7XG59O1xuXG5mdW5jdGlvbiB2YWxpZGF0ZUNsYXNzTmFtZUZvclRyaWdnZXJzKGNsYXNzTmFtZSwgdHlwZSkge1xuICBpZiAodHlwZSA9PSBUeXBlcy5iZWZvcmVTYXZlICYmIGNsYXNzTmFtZSA9PT0gJ19QdXNoU3RhdHVzJykge1xuICAgIC8vIF9QdXNoU3RhdHVzIHVzZXMgdW5kb2N1bWVudGVkIG5lc3RlZCBrZXkgaW5jcmVtZW50IG9wc1xuICAgIC8vIGFsbG93aW5nIGJlZm9yZVNhdmUgd291bGQgbWVzcyB1cCB0aGUgb2JqZWN0cyBiaWcgdGltZVxuICAgIC8vIFRPRE86IEFsbG93IHByb3BlciBkb2N1bWVudGVkIHdheSBvZiB1c2luZyBuZXN0ZWQgaW5jcmVtZW50IG9wc1xuICAgIHRocm93ICdPbmx5IGFmdGVyU2F2ZSBpcyBhbGxvd2VkIG9uIF9QdXNoU3RhdHVzJztcbiAgfVxuICBpZiAoKHR5cGUgPT09IFR5cGVzLmJlZm9yZUxvZ2luIHx8IHR5cGUgPT09IFR5cGVzLmFmdGVyTG9naW4pICYmIGNsYXNzTmFtZSAhPT0gJ19Vc2VyJykge1xuICAgIC8vIFRPRE86IGNoZWNrIGlmIHVwc3RyZWFtIGNvZGUgd2lsbCBoYW5kbGUgYEVycm9yYCBpbnN0YW5jZSByYXRoZXJcbiAgICAvLyB0aGFuIHRoaXMgYW50aS1wYXR0ZXJuIG9mIHRocm93aW5nIHN0cmluZ3NcbiAgICB0aHJvdyAnT25seSB0aGUgX1VzZXIgY2xhc3MgaXMgYWxsb3dlZCBmb3IgdGhlIGJlZm9yZUxvZ2luIGFuZCBhZnRlckxvZ2luIHRyaWdnZXJzJztcbiAgfVxuICBpZiAodHlwZSA9PT0gVHlwZXMuYWZ0ZXJMb2dvdXQgJiYgY2xhc3NOYW1lICE9PSAnX1Nlc3Npb24nKSB7XG4gICAgLy8gVE9ETzogY2hlY2sgaWYgdXBzdHJlYW0gY29kZSB3aWxsIGhhbmRsZSBgRXJyb3JgIGluc3RhbmNlIHJhdGhlclxuICAgIC8vIHRoYW4gdGhpcyBhbnRpLXBhdHRlcm4gb2YgdGhyb3dpbmcgc3RyaW5nc1xuICAgIHRocm93ICdPbmx5IHRoZSBfU2Vzc2lvbiBjbGFzcyBpcyBhbGxvd2VkIGZvciB0aGUgYWZ0ZXJMb2dvdXQgdHJpZ2dlci4nO1xuICB9XG4gIGlmIChjbGFzc05hbWUgPT09ICdfU2Vzc2lvbicgJiYgdHlwZSAhPT0gVHlwZXMuYWZ0ZXJMb2dvdXQpIHtcbiAgICAvLyBUT0RPOiBjaGVjayBpZiB1cHN0cmVhbSBjb2RlIHdpbGwgaGFuZGxlIGBFcnJvcmAgaW5zdGFuY2UgcmF0aGVyXG4gICAgLy8gdGhhbiB0aGlzIGFudGktcGF0dGVybiBvZiB0aHJvd2luZyBzdHJpbmdzXG4gICAgdGhyb3cgJ09ubHkgdGhlIGFmdGVyTG9nb3V0IHRyaWdnZXIgaXMgYWxsb3dlZCBmb3IgdGhlIF9TZXNzaW9uIGNsYXNzLic7XG4gIH1cbiAgcmV0dXJuIGNsYXNzTmFtZTtcbn1cblxuY29uc3QgX3RyaWdnZXJTdG9yZSA9IHt9O1xuXG5jb25zdCBDYXRlZ29yeSA9IHtcbiAgRnVuY3Rpb25zOiAnRnVuY3Rpb25zJyxcbiAgVmFsaWRhdG9yczogJ1ZhbGlkYXRvcnMnLFxuICBKb2JzOiAnSm9icycsXG4gIFRyaWdnZXJzOiAnVHJpZ2dlcnMnLFxufTtcblxuZnVuY3Rpb24gZ2V0U3RvcmUoY2F0ZWdvcnksIG5hbWUsIGFwcGxpY2F0aW9uSWQpIHtcbiAgY29uc3QgcGF0aCA9IG5hbWUuc3BsaXQoJy4nKTtcbiAgcGF0aC5zcGxpY2UoLTEpOyAvLyByZW1vdmUgbGFzdCBjb21wb25lbnRcbiAgYXBwbGljYXRpb25JZCA9IGFwcGxpY2F0aW9uSWQgfHwgUGFyc2UuYXBwbGljYXRpb25JZDtcbiAgX3RyaWdnZXJTdG9yZVthcHBsaWNhdGlvbklkXSA9IF90cmlnZ2VyU3RvcmVbYXBwbGljYXRpb25JZF0gfHwgYmFzZVN0b3JlKCk7XG4gIGxldCBzdG9yZSA9IF90cmlnZ2VyU3RvcmVbYXBwbGljYXRpb25JZF1bY2F0ZWdvcnldO1xuICBmb3IgKGNvbnN0IGNvbXBvbmVudCBvZiBwYXRoKSB7XG4gICAgc3RvcmUgPSBzdG9yZVtjb21wb25lbnRdO1xuICAgIGlmICghc3RvcmUpIHtcbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuICB9XG4gIHJldHVybiBzdG9yZTtcbn1cblxuZnVuY3Rpb24gYWRkKGNhdGVnb3J5LCBuYW1lLCBoYW5kbGVyLCBhcHBsaWNhdGlvbklkKSB7XG4gIGNvbnN0IGxhc3RDb21wb25lbnQgPSBuYW1lLnNwbGl0KCcuJykuc3BsaWNlKC0xKTtcbiAgY29uc3Qgc3RvcmUgPSBnZXRTdG9yZShjYXRlZ29yeSwgbmFtZSwgYXBwbGljYXRpb25JZCk7XG4gIGlmIChzdG9yZVtsYXN0Q29tcG9uZW50XSkge1xuICAgIGxvZ2dlci53YXJuKFxuICAgICAgYFdhcm5pbmc6IER1cGxpY2F0ZSBjbG91ZCBmdW5jdGlvbnMgZXhpc3QgZm9yICR7bGFzdENvbXBvbmVudH0uIE9ubHkgdGhlIGxhc3Qgb25lIHdpbGwgYmUgdXNlZCBhbmQgdGhlIG90aGVycyB3aWxsIGJlIGlnbm9yZWQuYFxuICAgICk7XG4gIH1cbiAgc3RvcmVbbGFzdENvbXBvbmVudF0gPSBoYW5kbGVyO1xufVxuXG5mdW5jdGlvbiByZW1vdmUoY2F0ZWdvcnksIG5hbWUsIGFwcGxpY2F0aW9uSWQpIHtcbiAgY29uc3QgbGFzdENvbXBvbmVudCA9IG5hbWUuc3BsaXQoJy4nKS5zcGxpY2UoLTEpO1xuICBjb25zdCBzdG9yZSA9IGdldFN0b3JlKGNhdGVnb3J5LCBuYW1lLCBhcHBsaWNhdGlvbklkKTtcbiAgZGVsZXRlIHN0b3JlW2xhc3RDb21wb25lbnRdO1xufVxuXG5mdW5jdGlvbiBnZXQoY2F0ZWdvcnksIG5hbWUsIGFwcGxpY2F0aW9uSWQpIHtcbiAgY29uc3QgbGFzdENvbXBvbmVudCA9IG5hbWUuc3BsaXQoJy4nKS5zcGxpY2UoLTEpO1xuICBjb25zdCBzdG9yZSA9IGdldFN0b3JlKGNhdGVnb3J5LCBuYW1lLCBhcHBsaWNhdGlvbklkKTtcbiAgcmV0dXJuIHN0b3JlW2xhc3RDb21wb25lbnRdO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gYWRkRnVuY3Rpb24oZnVuY3Rpb25OYW1lLCBoYW5kbGVyLCB2YWxpZGF0aW9uSGFuZGxlciwgYXBwbGljYXRpb25JZCkge1xuICBhZGQoQ2F0ZWdvcnkuRnVuY3Rpb25zLCBmdW5jdGlvbk5hbWUsIGhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpO1xuICBhZGQoQ2F0ZWdvcnkuVmFsaWRhdG9ycywgZnVuY3Rpb25OYW1lLCB2YWxpZGF0aW9uSGFuZGxlciwgYXBwbGljYXRpb25JZCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBhZGRKb2Ioam9iTmFtZSwgaGFuZGxlciwgYXBwbGljYXRpb25JZCkge1xuICBhZGQoQ2F0ZWdvcnkuSm9icywgam9iTmFtZSwgaGFuZGxlciwgYXBwbGljYXRpb25JZCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBhZGRUcmlnZ2VyKHR5cGUsIGNsYXNzTmFtZSwgaGFuZGxlciwgYXBwbGljYXRpb25JZCwgdmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgdmFsaWRhdGVDbGFzc05hbWVGb3JUcmlnZ2VycyhjbGFzc05hbWUsIHR5cGUpO1xuICBhZGQoQ2F0ZWdvcnkuVHJpZ2dlcnMsIGAke3R5cGV9LiR7Y2xhc3NOYW1lfWAsIGhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpO1xuICBhZGQoQ2F0ZWdvcnkuVmFsaWRhdG9ycywgYCR7dHlwZX0uJHtjbGFzc05hbWV9YCwgdmFsaWRhdGlvbkhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gYWRkRmlsZVRyaWdnZXIodHlwZSwgaGFuZGxlciwgYXBwbGljYXRpb25JZCwgdmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgYWRkKENhdGVnb3J5LlRyaWdnZXJzLCBgJHt0eXBlfS4ke0ZpbGVDbGFzc05hbWV9YCwgaGFuZGxlciwgYXBwbGljYXRpb25JZCk7XG4gIGFkZChDYXRlZ29yeS5WYWxpZGF0b3JzLCBgJHt0eXBlfS4ke0ZpbGVDbGFzc05hbWV9YCwgdmFsaWRhdGlvbkhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gYWRkQ29ubmVjdFRyaWdnZXIodHlwZSwgaGFuZGxlciwgYXBwbGljYXRpb25JZCwgdmFsaWRhdGlvbkhhbmRsZXIpIHtcbiAgYWRkKENhdGVnb3J5LlRyaWdnZXJzLCBgJHt0eXBlfS4ke0Nvbm5lY3RDbGFzc05hbWV9YCwgaGFuZGxlciwgYXBwbGljYXRpb25JZCk7XG4gIGFkZChDYXRlZ29yeS5WYWxpZGF0b3JzLCBgJHt0eXBlfS4ke0Nvbm5lY3RDbGFzc05hbWV9YCwgdmFsaWRhdGlvbkhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gYWRkTGl2ZVF1ZXJ5RXZlbnRIYW5kbGVyKGhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpIHtcbiAgYXBwbGljYXRpb25JZCA9IGFwcGxpY2F0aW9uSWQgfHwgUGFyc2UuYXBwbGljYXRpb25JZDtcbiAgX3RyaWdnZXJTdG9yZVthcHBsaWNhdGlvbklkXSA9IF90cmlnZ2VyU3RvcmVbYXBwbGljYXRpb25JZF0gfHwgYmFzZVN0b3JlKCk7XG4gIF90cmlnZ2VyU3RvcmVbYXBwbGljYXRpb25JZF0uTGl2ZVF1ZXJ5LnB1c2goaGFuZGxlcik7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZW1vdmVGdW5jdGlvbihmdW5jdGlvbk5hbWUsIGFwcGxpY2F0aW9uSWQpIHtcbiAgcmVtb3ZlKENhdGVnb3J5LkZ1bmN0aW9ucywgZnVuY3Rpb25OYW1lLCBhcHBsaWNhdGlvbklkKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHJlbW92ZVRyaWdnZXIodHlwZSwgY2xhc3NOYW1lLCBhcHBsaWNhdGlvbklkKSB7XG4gIHJlbW92ZShDYXRlZ29yeS5UcmlnZ2VycywgYCR7dHlwZX0uJHtjbGFzc05hbWV9YCwgYXBwbGljYXRpb25JZCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBfdW5yZWdpc3RlckFsbCgpIHtcbiAgT2JqZWN0LmtleXMoX3RyaWdnZXJTdG9yZSkuZm9yRWFjaChhcHBJZCA9PiBkZWxldGUgX3RyaWdnZXJTdG9yZVthcHBJZF0pO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0VHJpZ2dlcihjbGFzc05hbWUsIHRyaWdnZXJUeXBlLCBhcHBsaWNhdGlvbklkKSB7XG4gIGlmICghYXBwbGljYXRpb25JZCkge1xuICAgIHRocm93ICdNaXNzaW5nIEFwcGxpY2F0aW9uSUQnO1xuICB9XG4gIHJldHVybiBnZXQoQ2F0ZWdvcnkuVHJpZ2dlcnMsIGAke3RyaWdnZXJUeXBlfS4ke2NsYXNzTmFtZX1gLCBhcHBsaWNhdGlvbklkKTtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHJ1blRyaWdnZXIodHJpZ2dlciwgbmFtZSwgcmVxdWVzdCwgYXV0aCkge1xuICBpZiAoIXRyaWdnZXIpIHtcbiAgICByZXR1cm47XG4gIH1cbiAgYXdhaXQgbWF5YmVSdW5WYWxpZGF0b3IocmVxdWVzdCwgbmFtZSwgYXV0aCk7XG4gIGlmIChyZXF1ZXN0LnNraXBXaXRoTWFzdGVyS2V5KSB7XG4gICAgcmV0dXJuO1xuICB9XG4gIHJldHVybiBhd2FpdCB0cmlnZ2VyKHJlcXVlc3QpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0RmlsZVRyaWdnZXIodHlwZSwgYXBwbGljYXRpb25JZCkge1xuICByZXR1cm4gZ2V0VHJpZ2dlcihGaWxlQ2xhc3NOYW1lLCB0eXBlLCBhcHBsaWNhdGlvbklkKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHRyaWdnZXJFeGlzdHMoY2xhc3NOYW1lOiBzdHJpbmcsIHR5cGU6IHN0cmluZywgYXBwbGljYXRpb25JZDogc3RyaW5nKTogYm9vbGVhbiB7XG4gIHJldHVybiBnZXRUcmlnZ2VyKGNsYXNzTmFtZSwgdHlwZSwgYXBwbGljYXRpb25JZCkgIT0gdW5kZWZpbmVkO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0RnVuY3Rpb24oZnVuY3Rpb25OYW1lLCBhcHBsaWNhdGlvbklkKSB7XG4gIHJldHVybiBnZXQoQ2F0ZWdvcnkuRnVuY3Rpb25zLCBmdW5jdGlvbk5hbWUsIGFwcGxpY2F0aW9uSWQpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0RnVuY3Rpb25OYW1lcyhhcHBsaWNhdGlvbklkKSB7XG4gIGNvbnN0IHN0b3JlID1cbiAgICAoX3RyaWdnZXJTdG9yZVthcHBsaWNhdGlvbklkXSAmJiBfdHJpZ2dlclN0b3JlW2FwcGxpY2F0aW9uSWRdW0NhdGVnb3J5LkZ1bmN0aW9uc10pIHx8IHt9O1xuICBjb25zdCBmdW5jdGlvbk5hbWVzID0gW107XG4gIGNvbnN0IGV4dHJhY3RGdW5jdGlvbk5hbWVzID0gKG5hbWVzcGFjZSwgc3RvcmUpID0+IHtcbiAgICBPYmplY3Qua2V5cyhzdG9yZSkuZm9yRWFjaChuYW1lID0+IHtcbiAgICAgIGNvbnN0IHZhbHVlID0gc3RvcmVbbmFtZV07XG4gICAgICBpZiAobmFtZXNwYWNlKSB7XG4gICAgICAgIG5hbWUgPSBgJHtuYW1lc3BhY2V9LiR7bmFtZX1gO1xuICAgICAgfVxuICAgICAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICBmdW5jdGlvbk5hbWVzLnB1c2gobmFtZSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBleHRyYWN0RnVuY3Rpb25OYW1lcyhuYW1lLCB2YWx1ZSk7XG4gICAgICB9XG4gICAgfSk7XG4gIH07XG4gIGV4dHJhY3RGdW5jdGlvbk5hbWVzKG51bGwsIHN0b3JlKTtcbiAgcmV0dXJuIGZ1bmN0aW9uTmFtZXM7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRKb2Ioam9iTmFtZSwgYXBwbGljYXRpb25JZCkge1xuICByZXR1cm4gZ2V0KENhdGVnb3J5LkpvYnMsIGpvYk5hbWUsIGFwcGxpY2F0aW9uSWQpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0Sm9icyhhcHBsaWNhdGlvbklkKSB7XG4gIHZhciBtYW5hZ2VyID0gX3RyaWdnZXJTdG9yZVthcHBsaWNhdGlvbklkXTtcbiAgaWYgKG1hbmFnZXIgJiYgbWFuYWdlci5Kb2JzKSB7XG4gICAgcmV0dXJuIG1hbmFnZXIuSm9icztcbiAgfVxuICByZXR1cm4gdW5kZWZpbmVkO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0VmFsaWRhdG9yKGZ1bmN0aW9uTmFtZSwgYXBwbGljYXRpb25JZCkge1xuICByZXR1cm4gZ2V0KENhdGVnb3J5LlZhbGlkYXRvcnMsIGZ1bmN0aW9uTmFtZSwgYXBwbGljYXRpb25JZCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRSZXF1ZXN0T2JqZWN0KFxuICB0cmlnZ2VyVHlwZSxcbiAgYXV0aCxcbiAgcGFyc2VPYmplY3QsXG4gIG9yaWdpbmFsUGFyc2VPYmplY3QsXG4gIGNvbmZpZyxcbiAgY29udGV4dFxuKSB7XG4gIGNvbnN0IHJlcXVlc3QgPSB7XG4gICAgdHJpZ2dlck5hbWU6IHRyaWdnZXJUeXBlLFxuICAgIG9iamVjdDogcGFyc2VPYmplY3QsXG4gICAgbWFzdGVyOiBmYWxzZSxcbiAgICBsb2c6IGNvbmZpZy5sb2dnZXJDb250cm9sbGVyLFxuICAgIGhlYWRlcnM6IGNvbmZpZy5oZWFkZXJzLFxuICAgIGlwOiBjb25maWcuaXAsXG4gIH07XG5cbiAgaWYgKG9yaWdpbmFsUGFyc2VPYmplY3QpIHtcbiAgICByZXF1ZXN0Lm9yaWdpbmFsID0gb3JpZ2luYWxQYXJzZU9iamVjdDtcbiAgfVxuICBpZiAoXG4gICAgdHJpZ2dlclR5cGUgPT09IFR5cGVzLmJlZm9yZVNhdmUgfHxcbiAgICB0cmlnZ2VyVHlwZSA9PT0gVHlwZXMuYWZ0ZXJTYXZlIHx8XG4gICAgdHJpZ2dlclR5cGUgPT09IFR5cGVzLmJlZm9yZURlbGV0ZSB8fFxuICAgIHRyaWdnZXJUeXBlID09PSBUeXBlcy5hZnRlckRlbGV0ZSB8fFxuICAgIHRyaWdnZXJUeXBlID09PSBUeXBlcy5hZnRlckZpbmRcbiAgKSB7XG4gICAgLy8gU2V0IGEgY29weSBvZiB0aGUgY29udGV4dCBvbiB0aGUgcmVxdWVzdCBvYmplY3QuXG4gICAgcmVxdWVzdC5jb250ZXh0ID0gT2JqZWN0LmFzc2lnbih7fSwgY29udGV4dCk7XG4gIH1cblxuICBpZiAoIWF1dGgpIHtcbiAgICByZXR1cm4gcmVxdWVzdDtcbiAgfVxuICBpZiAoYXV0aC5pc01hc3Rlcikge1xuICAgIHJlcXVlc3RbJ21hc3RlciddID0gdHJ1ZTtcbiAgfVxuICBpZiAoYXV0aC51c2VyKSB7XG4gICAgcmVxdWVzdFsndXNlciddID0gYXV0aC51c2VyO1xuICB9XG4gIGlmIChhdXRoLmluc3RhbGxhdGlvbklkKSB7XG4gICAgcmVxdWVzdFsnaW5zdGFsbGF0aW9uSWQnXSA9IGF1dGguaW5zdGFsbGF0aW9uSWQ7XG4gIH1cbiAgcmV0dXJuIHJlcXVlc3Q7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRSZXF1ZXN0UXVlcnlPYmplY3QodHJpZ2dlclR5cGUsIGF1dGgsIHF1ZXJ5LCBjb3VudCwgY29uZmlnLCBjb250ZXh0LCBpc0dldCkge1xuICBpc0dldCA9ICEhaXNHZXQ7XG5cbiAgdmFyIHJlcXVlc3QgPSB7XG4gICAgdHJpZ2dlck5hbWU6IHRyaWdnZXJUeXBlLFxuICAgIHF1ZXJ5LFxuICAgIG1hc3RlcjogZmFsc2UsXG4gICAgY291bnQsXG4gICAgbG9nOiBjb25maWcubG9nZ2VyQ29udHJvbGxlcixcbiAgICBpc0dldCxcbiAgICBoZWFkZXJzOiBjb25maWcuaGVhZGVycyxcbiAgICBpcDogY29uZmlnLmlwLFxuICAgIGNvbnRleHQ6IGNvbnRleHQgfHwge30sXG4gIH07XG5cbiAgaWYgKCFhdXRoKSB7XG4gICAgcmV0dXJuIHJlcXVlc3Q7XG4gIH1cbiAgaWYgKGF1dGguaXNNYXN0ZXIpIHtcbiAgICByZXF1ZXN0WydtYXN0ZXInXSA9IHRydWU7XG4gIH1cbiAgaWYgKGF1dGgudXNlcikge1xuICAgIHJlcXVlc3RbJ3VzZXInXSA9IGF1dGgudXNlcjtcbiAgfVxuICBpZiAoYXV0aC5pbnN0YWxsYXRpb25JZCkge1xuICAgIHJlcXVlc3RbJ2luc3RhbGxhdGlvbklkJ10gPSBhdXRoLmluc3RhbGxhdGlvbklkO1xuICB9XG4gIHJldHVybiByZXF1ZXN0O1xufVxuXG4vLyBDcmVhdGVzIHRoZSByZXNwb25zZSBvYmplY3QsIGFuZCB1c2VzIHRoZSByZXF1ZXN0IG9iamVjdCB0byBwYXNzIGRhdGFcbi8vIFRoZSBBUEkgd2lsbCBjYWxsIHRoaXMgd2l0aCBSRVNUIEFQSSBmb3JtYXR0ZWQgb2JqZWN0cywgdGhpcyB3aWxsXG4vLyB0cmFuc2Zvcm0gdGhlbSB0byBQYXJzZS5PYmplY3QgaW5zdGFuY2VzIGV4cGVjdGVkIGJ5IENsb3VkIENvZGUuXG4vLyBBbnkgY2hhbmdlcyBtYWRlIHRvIHRoZSBvYmplY3QgaW4gYSBiZWZvcmVTYXZlIHdpbGwgYmUgaW5jbHVkZWQuXG5leHBvcnQgZnVuY3Rpb24gZ2V0UmVzcG9uc2VPYmplY3QocmVxdWVzdCwgcmVzb2x2ZSwgcmVqZWN0KSB7XG4gIHJldHVybiB7XG4gICAgc3VjY2VzczogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICBpZiAocmVxdWVzdC50cmlnZ2VyTmFtZSA9PT0gVHlwZXMuYWZ0ZXJGaW5kKSB7XG4gICAgICAgIGlmICghcmVzcG9uc2UpIHtcbiAgICAgICAgICByZXNwb25zZSA9IHJlcXVlc3Qub2JqZWN0cztcbiAgICAgICAgfVxuICAgICAgICByZXNwb25zZSA9IHJlc3BvbnNlLm1hcChvYmplY3QgPT4ge1xuICAgICAgICAgIHJldHVybiBvYmplY3QudG9KU09OKCk7XG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gcmVzb2x2ZShyZXNwb25zZSk7XG4gICAgICB9XG4gICAgICAvLyBVc2UgdGhlIEpTT04gcmVzcG9uc2VcbiAgICAgIGlmIChcbiAgICAgICAgcmVzcG9uc2UgJiZcbiAgICAgICAgdHlwZW9mIHJlc3BvbnNlID09PSAnb2JqZWN0JyAmJlxuICAgICAgICAhcmVxdWVzdC5vYmplY3QuZXF1YWxzKHJlc3BvbnNlKSAmJlxuICAgICAgICByZXF1ZXN0LnRyaWdnZXJOYW1lID09PSBUeXBlcy5iZWZvcmVTYXZlXG4gICAgICApIHtcbiAgICAgICAgcmV0dXJuIHJlc29sdmUocmVzcG9uc2UpO1xuICAgICAgfVxuICAgICAgaWYgKHJlc3BvbnNlICYmIHR5cGVvZiByZXNwb25zZSA9PT0gJ29iamVjdCcgJiYgcmVxdWVzdC50cmlnZ2VyTmFtZSA9PT0gVHlwZXMuYWZ0ZXJTYXZlKSB7XG4gICAgICAgIHJldHVybiByZXNvbHZlKHJlc3BvbnNlKTtcbiAgICAgIH1cbiAgICAgIGlmIChyZXF1ZXN0LnRyaWdnZXJOYW1lID09PSBUeXBlcy5hZnRlclNhdmUpIHtcbiAgICAgICAgcmV0dXJuIHJlc29sdmUoKTtcbiAgICAgIH1cbiAgICAgIHJlc3BvbnNlID0ge307XG4gICAgICBpZiAocmVxdWVzdC50cmlnZ2VyTmFtZSA9PT0gVHlwZXMuYmVmb3JlU2F2ZSkge1xuICAgICAgICByZXNwb25zZVsnb2JqZWN0J10gPSByZXF1ZXN0Lm9iamVjdC5fZ2V0U2F2ZUpTT04oKTtcbiAgICAgICAgcmVzcG9uc2VbJ29iamVjdCddWydvYmplY3RJZCddID0gcmVxdWVzdC5vYmplY3QuaWQ7XG4gICAgICB9XG4gICAgICByZXR1cm4gcmVzb2x2ZShyZXNwb25zZSk7XG4gICAgfSxcbiAgICBlcnJvcjogZnVuY3Rpb24gKGVycm9yKSB7XG4gICAgICBjb25zdCBlID0gcmVzb2x2ZUVycm9yKGVycm9yLCB7XG4gICAgICAgIGNvZGU6IFBhcnNlLkVycm9yLlNDUklQVF9GQUlMRUQsXG4gICAgICAgIG1lc3NhZ2U6ICdTY3JpcHQgZmFpbGVkLiBVbmtub3duIGVycm9yLicsXG4gICAgICB9KTtcbiAgICAgIHJlamVjdChlKTtcbiAgICB9LFxuICB9O1xufVxuXG5mdW5jdGlvbiB1c2VySWRGb3JMb2coYXV0aCkge1xuICByZXR1cm4gYXV0aCAmJiBhdXRoLnVzZXIgPyBhdXRoLnVzZXIuaWQgOiB1bmRlZmluZWQ7XG59XG5cbmZ1bmN0aW9uIGxvZ1RyaWdnZXJBZnRlckhvb2sodHJpZ2dlclR5cGUsIGNsYXNzTmFtZSwgaW5wdXQsIGF1dGgpIHtcbiAgY29uc3QgY2xlYW5JbnB1dCA9IGxvZ2dlci50cnVuY2F0ZUxvZ01lc3NhZ2UoSlNPTi5zdHJpbmdpZnkoaW5wdXQpKTtcbiAgbG9nZ2VyLmluZm8oXG4gICAgYCR7dHJpZ2dlclR5cGV9IHRyaWdnZXJlZCBmb3IgJHtjbGFzc05hbWV9IGZvciB1c2VyICR7dXNlcklkRm9yTG9nKFxuICAgICAgYXV0aFxuICAgICl9OlxcbiAgSW5wdXQ6ICR7Y2xlYW5JbnB1dH1gLFxuICAgIHtcbiAgICAgIGNsYXNzTmFtZSxcbiAgICAgIHRyaWdnZXJUeXBlLFxuICAgICAgdXNlcjogdXNlcklkRm9yTG9nKGF1dGgpLFxuICAgIH1cbiAgKTtcbn1cblxuZnVuY3Rpb24gbG9nVHJpZ2dlclN1Y2Nlc3NCZWZvcmVIb29rKHRyaWdnZXJUeXBlLCBjbGFzc05hbWUsIGlucHV0LCByZXN1bHQsIGF1dGgpIHtcbiAgY29uc3QgY2xlYW5JbnB1dCA9IGxvZ2dlci50cnVuY2F0ZUxvZ01lc3NhZ2UoSlNPTi5zdHJpbmdpZnkoaW5wdXQpKTtcbiAgY29uc3QgY2xlYW5SZXN1bHQgPSBsb2dnZXIudHJ1bmNhdGVMb2dNZXNzYWdlKEpTT04uc3RyaW5naWZ5KHJlc3VsdCkpO1xuICBsb2dnZXIuaW5mbyhcbiAgICBgJHt0cmlnZ2VyVHlwZX0gdHJpZ2dlcmVkIGZvciAke2NsYXNzTmFtZX0gZm9yIHVzZXIgJHt1c2VySWRGb3JMb2coXG4gICAgICBhdXRoXG4gICAgKX06XFxuICBJbnB1dDogJHtjbGVhbklucHV0fVxcbiAgUmVzdWx0OiAke2NsZWFuUmVzdWx0fWAsXG4gICAge1xuICAgICAgY2xhc3NOYW1lLFxuICAgICAgdHJpZ2dlclR5cGUsXG4gICAgICB1c2VyOiB1c2VySWRGb3JMb2coYXV0aCksXG4gICAgfVxuICApO1xufVxuXG5mdW5jdGlvbiBsb2dUcmlnZ2VyRXJyb3JCZWZvcmVIb29rKHRyaWdnZXJUeXBlLCBjbGFzc05hbWUsIGlucHV0LCBhdXRoLCBlcnJvcikge1xuICBjb25zdCBjbGVhbklucHV0ID0gbG9nZ2VyLnRydW5jYXRlTG9nTWVzc2FnZShKU09OLnN0cmluZ2lmeShpbnB1dCkpO1xuICBsb2dnZXIuZXJyb3IoXG4gICAgYCR7dHJpZ2dlclR5cGV9IGZhaWxlZCBmb3IgJHtjbGFzc05hbWV9IGZvciB1c2VyICR7dXNlcklkRm9yTG9nKFxuICAgICAgYXV0aFxuICAgICl9OlxcbiAgSW5wdXQ6ICR7Y2xlYW5JbnB1dH1cXG4gIEVycm9yOiAke0pTT04uc3RyaW5naWZ5KGVycm9yKX1gLFxuICAgIHtcbiAgICAgIGNsYXNzTmFtZSxcbiAgICAgIHRyaWdnZXJUeXBlLFxuICAgICAgZXJyb3IsXG4gICAgICB1c2VyOiB1c2VySWRGb3JMb2coYXV0aCksXG4gICAgfVxuICApO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gbWF5YmVSdW5BZnRlckZpbmRUcmlnZ2VyKFxuICB0cmlnZ2VyVHlwZSxcbiAgYXV0aCxcbiAgY2xhc3NOYW1lLFxuICBvYmplY3RzLFxuICBjb25maWcsXG4gIHF1ZXJ5LFxuICBjb250ZXh0XG4pIHtcbiAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcbiAgICBjb25zdCB0cmlnZ2VyID0gZ2V0VHJpZ2dlcihjbGFzc05hbWUsIHRyaWdnZXJUeXBlLCBjb25maWcuYXBwbGljYXRpb25JZCk7XG4gICAgaWYgKCF0cmlnZ2VyKSB7XG4gICAgICByZXR1cm4gcmVzb2x2ZSgpO1xuICAgIH1cbiAgICBjb25zdCByZXF1ZXN0ID0gZ2V0UmVxdWVzdE9iamVjdCh0cmlnZ2VyVHlwZSwgYXV0aCwgbnVsbCwgbnVsbCwgY29uZmlnLCBjb250ZXh0KTtcbiAgICBpZiAocXVlcnkpIHtcbiAgICAgIHJlcXVlc3QucXVlcnkgPSBxdWVyeTtcbiAgICB9XG4gICAgY29uc3QgeyBzdWNjZXNzLCBlcnJvciB9ID0gZ2V0UmVzcG9uc2VPYmplY3QoXG4gICAgICByZXF1ZXN0LFxuICAgICAgb2JqZWN0ID0+IHtcbiAgICAgICAgcmVzb2x2ZShvYmplY3QpO1xuICAgICAgfSxcbiAgICAgIGVycm9yID0+IHtcbiAgICAgICAgcmVqZWN0KGVycm9yKTtcbiAgICAgIH1cbiAgICApO1xuICAgIGxvZ1RyaWdnZXJTdWNjZXNzQmVmb3JlSG9vayh0cmlnZ2VyVHlwZSwgY2xhc3NOYW1lLCAnQWZ0ZXJGaW5kJywgSlNPTi5zdHJpbmdpZnkob2JqZWN0cyksIGF1dGgpO1xuICAgIHJlcXVlc3Qub2JqZWN0cyA9IG9iamVjdHMubWFwKG9iamVjdCA9PiB7XG4gICAgICAvL3NldHRpbmcgdGhlIGNsYXNzIG5hbWUgdG8gdHJhbnNmb3JtIGludG8gcGFyc2Ugb2JqZWN0XG4gICAgICBvYmplY3QuY2xhc3NOYW1lID0gY2xhc3NOYW1lO1xuICAgICAgcmV0dXJuIFBhcnNlLk9iamVjdC5mcm9tSlNPTihvYmplY3QpO1xuICAgIH0pO1xuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKVxuICAgICAgLnRoZW4oKCkgPT4ge1xuICAgICAgICByZXR1cm4gbWF5YmVSdW5WYWxpZGF0b3IocmVxdWVzdCwgYCR7dHJpZ2dlclR5cGV9LiR7Y2xhc3NOYW1lfWAsIGF1dGgpO1xuICAgICAgfSlcbiAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgaWYgKHJlcXVlc3Quc2tpcFdpdGhNYXN0ZXJLZXkpIHtcbiAgICAgICAgICByZXR1cm4gcmVxdWVzdC5vYmplY3RzO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHJlc3BvbnNlID0gdHJpZ2dlcihyZXF1ZXN0KTtcbiAgICAgICAgaWYgKHJlc3BvbnNlICYmIHR5cGVvZiByZXNwb25zZS50aGVuID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLnRoZW4ocmVzdWx0cyA9PiB7XG4gICAgICAgICAgICBpZiAoIXJlc3VsdHMpIHtcbiAgICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICAgIFBhcnNlLkVycm9yLlNDUklQVF9GQUlMRUQsXG4gICAgICAgICAgICAgICAgJ0FmdGVyRmluZCBleHBlY3QgcmVzdWx0cyB0byBiZSByZXR1cm5lZCBpbiB0aGUgcHJvbWlzZSdcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiByZXN1bHRzO1xuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgIH0pXG4gICAgICAudGhlbihzdWNjZXNzLCBlcnJvcik7XG4gIH0pLnRoZW4ocmVzdWx0cyA9PiB7XG4gICAgbG9nVHJpZ2dlckFmdGVySG9vayh0cmlnZ2VyVHlwZSwgY2xhc3NOYW1lLCBKU09OLnN0cmluZ2lmeShyZXN1bHRzKSwgYXV0aCk7XG4gICAgcmV0dXJuIHJlc3VsdHM7XG4gIH0pO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gbWF5YmVSdW5RdWVyeVRyaWdnZXIoXG4gIHRyaWdnZXJUeXBlLFxuICBjbGFzc05hbWUsXG4gIHJlc3RXaGVyZSxcbiAgcmVzdE9wdGlvbnMsXG4gIGNvbmZpZyxcbiAgYXV0aCxcbiAgY29udGV4dCxcbiAgaXNHZXRcbikge1xuICBjb25zdCB0cmlnZ2VyID0gZ2V0VHJpZ2dlcihjbGFzc05hbWUsIHRyaWdnZXJUeXBlLCBjb25maWcuYXBwbGljYXRpb25JZCk7XG4gIGlmICghdHJpZ2dlcikge1xuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoe1xuICAgICAgcmVzdFdoZXJlLFxuICAgICAgcmVzdE9wdGlvbnMsXG4gICAgfSk7XG4gIH1cbiAgY29uc3QganNvbiA9IE9iamVjdC5hc3NpZ24oe30sIHJlc3RPcHRpb25zKTtcbiAganNvbi53aGVyZSA9IHJlc3RXaGVyZTtcblxuICBjb25zdCBwYXJzZVF1ZXJ5ID0gbmV3IFBhcnNlLlF1ZXJ5KGNsYXNzTmFtZSk7XG4gIHBhcnNlUXVlcnkud2l0aEpTT04oanNvbik7XG5cbiAgbGV0IGNvdW50ID0gZmFsc2U7XG4gIGlmIChyZXN0T3B0aW9ucykge1xuICAgIGNvdW50ID0gISFyZXN0T3B0aW9ucy5jb3VudDtcbiAgfVxuICBjb25zdCByZXF1ZXN0T2JqZWN0ID0gZ2V0UmVxdWVzdFF1ZXJ5T2JqZWN0KFxuICAgIHRyaWdnZXJUeXBlLFxuICAgIGF1dGgsXG4gICAgcGFyc2VRdWVyeSxcbiAgICBjb3VudCxcbiAgICBjb25maWcsXG4gICAgY29udGV4dCxcbiAgICBpc0dldFxuICApO1xuICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKClcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICByZXR1cm4gbWF5YmVSdW5WYWxpZGF0b3IocmVxdWVzdE9iamVjdCwgYCR7dHJpZ2dlclR5cGV9LiR7Y2xhc3NOYW1lfWAsIGF1dGgpO1xuICAgIH0pXG4gICAgLnRoZW4oKCkgPT4ge1xuICAgICAgaWYgKHJlcXVlc3RPYmplY3Quc2tpcFdpdGhNYXN0ZXJLZXkpIHtcbiAgICAgICAgcmV0dXJuIHJlcXVlc3RPYmplY3QucXVlcnk7XG4gICAgICB9XG4gICAgICByZXR1cm4gdHJpZ2dlcihyZXF1ZXN0T2JqZWN0KTtcbiAgICB9KVxuICAgIC50aGVuKFxuICAgICAgcmVzdWx0ID0+IHtcbiAgICAgICAgbGV0IHF1ZXJ5UmVzdWx0ID0gcGFyc2VRdWVyeTtcbiAgICAgICAgaWYgKHJlc3VsdCAmJiByZXN1bHQgaW5zdGFuY2VvZiBQYXJzZS5RdWVyeSkge1xuICAgICAgICAgIHF1ZXJ5UmVzdWx0ID0gcmVzdWx0O1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IGpzb25RdWVyeSA9IHF1ZXJ5UmVzdWx0LnRvSlNPTigpO1xuICAgICAgICBpZiAoanNvblF1ZXJ5LndoZXJlKSB7XG4gICAgICAgICAgcmVzdFdoZXJlID0ganNvblF1ZXJ5LndoZXJlO1xuICAgICAgICB9XG4gICAgICAgIGlmIChqc29uUXVlcnkubGltaXQpIHtcbiAgICAgICAgICByZXN0T3B0aW9ucyA9IHJlc3RPcHRpb25zIHx8IHt9O1xuICAgICAgICAgIHJlc3RPcHRpb25zLmxpbWl0ID0ganNvblF1ZXJ5LmxpbWl0O1xuICAgICAgICB9XG4gICAgICAgIGlmIChqc29uUXVlcnkuc2tpcCkge1xuICAgICAgICAgIHJlc3RPcHRpb25zID0gcmVzdE9wdGlvbnMgfHwge307XG4gICAgICAgICAgcmVzdE9wdGlvbnMuc2tpcCA9IGpzb25RdWVyeS5za2lwO1xuICAgICAgICB9XG4gICAgICAgIGlmIChqc29uUXVlcnkuaW5jbHVkZSkge1xuICAgICAgICAgIHJlc3RPcHRpb25zID0gcmVzdE9wdGlvbnMgfHwge307XG4gICAgICAgICAgcmVzdE9wdGlvbnMuaW5jbHVkZSA9IGpzb25RdWVyeS5pbmNsdWRlO1xuICAgICAgICB9XG4gICAgICAgIGlmIChqc29uUXVlcnkuZXhjbHVkZUtleXMpIHtcbiAgICAgICAgICByZXN0T3B0aW9ucyA9IHJlc3RPcHRpb25zIHx8IHt9O1xuICAgICAgICAgIHJlc3RPcHRpb25zLmV4Y2x1ZGVLZXlzID0ganNvblF1ZXJ5LmV4Y2x1ZGVLZXlzO1xuICAgICAgICB9XG4gICAgICAgIGlmIChqc29uUXVlcnkuZXhwbGFpbikge1xuICAgICAgICAgIHJlc3RPcHRpb25zID0gcmVzdE9wdGlvbnMgfHwge307XG4gICAgICAgICAgcmVzdE9wdGlvbnMuZXhwbGFpbiA9IGpzb25RdWVyeS5leHBsYWluO1xuICAgICAgICB9XG4gICAgICAgIGlmIChqc29uUXVlcnkua2V5cykge1xuICAgICAgICAgIHJlc3RPcHRpb25zID0gcmVzdE9wdGlvbnMgfHwge307XG4gICAgICAgICAgcmVzdE9wdGlvbnMua2V5cyA9IGpzb25RdWVyeS5rZXlzO1xuICAgICAgICB9XG4gICAgICAgIGlmIChqc29uUXVlcnkub3JkZXIpIHtcbiAgICAgICAgICByZXN0T3B0aW9ucyA9IHJlc3RPcHRpb25zIHx8IHt9O1xuICAgICAgICAgIHJlc3RPcHRpb25zLm9yZGVyID0ganNvblF1ZXJ5Lm9yZGVyO1xuICAgICAgICB9XG4gICAgICAgIGlmIChqc29uUXVlcnkuaGludCkge1xuICAgICAgICAgIHJlc3RPcHRpb25zID0gcmVzdE9wdGlvbnMgfHwge307XG4gICAgICAgICAgcmVzdE9wdGlvbnMuaGludCA9IGpzb25RdWVyeS5oaW50O1xuICAgICAgICB9XG4gICAgICAgIGlmIChyZXF1ZXN0T2JqZWN0LnJlYWRQcmVmZXJlbmNlKSB7XG4gICAgICAgICAgcmVzdE9wdGlvbnMgPSByZXN0T3B0aW9ucyB8fCB7fTtcbiAgICAgICAgICByZXN0T3B0aW9ucy5yZWFkUHJlZmVyZW5jZSA9IHJlcXVlc3RPYmplY3QucmVhZFByZWZlcmVuY2U7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHJlcXVlc3RPYmplY3QuaW5jbHVkZVJlYWRQcmVmZXJlbmNlKSB7XG4gICAgICAgICAgcmVzdE9wdGlvbnMgPSByZXN0T3B0aW9ucyB8fCB7fTtcbiAgICAgICAgICByZXN0T3B0aW9ucy5pbmNsdWRlUmVhZFByZWZlcmVuY2UgPSByZXF1ZXN0T2JqZWN0LmluY2x1ZGVSZWFkUHJlZmVyZW5jZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAocmVxdWVzdE9iamVjdC5zdWJxdWVyeVJlYWRQcmVmZXJlbmNlKSB7XG4gICAgICAgICAgcmVzdE9wdGlvbnMgPSByZXN0T3B0aW9ucyB8fCB7fTtcbiAgICAgICAgICByZXN0T3B0aW9ucy5zdWJxdWVyeVJlYWRQcmVmZXJlbmNlID0gcmVxdWVzdE9iamVjdC5zdWJxdWVyeVJlYWRQcmVmZXJlbmNlO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgcmVzdFdoZXJlLFxuICAgICAgICAgIHJlc3RPcHRpb25zLFxuICAgICAgICB9O1xuICAgICAgfSxcbiAgICAgIGVyciA9PiB7XG4gICAgICAgIGNvbnN0IGVycm9yID0gcmVzb2x2ZUVycm9yKGVyciwge1xuICAgICAgICAgIGNvZGU6IFBhcnNlLkVycm9yLlNDUklQVF9GQUlMRUQsXG4gICAgICAgICAgbWVzc2FnZTogJ1NjcmlwdCBmYWlsZWQuIFVua25vd24gZXJyb3IuJyxcbiAgICAgICAgfSk7XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfVxuICAgICk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZXNvbHZlRXJyb3IobWVzc2FnZSwgZGVmYXVsdE9wdHMpIHtcbiAgaWYgKCFkZWZhdWx0T3B0cykge1xuICAgIGRlZmF1bHRPcHRzID0ge307XG4gIH1cbiAgaWYgKCFtZXNzYWdlKSB7XG4gICAgcmV0dXJuIG5ldyBQYXJzZS5FcnJvcihcbiAgICAgIGRlZmF1bHRPcHRzLmNvZGUgfHwgUGFyc2UuRXJyb3IuU0NSSVBUX0ZBSUxFRCxcbiAgICAgIGRlZmF1bHRPcHRzLm1lc3NhZ2UgfHwgJ1NjcmlwdCBmYWlsZWQuJ1xuICAgICk7XG4gIH1cbiAgaWYgKG1lc3NhZ2UgaW5zdGFuY2VvZiBQYXJzZS5FcnJvcikge1xuICAgIHJldHVybiBtZXNzYWdlO1xuICB9XG5cbiAgY29uc3QgY29kZSA9IGRlZmF1bHRPcHRzLmNvZGUgfHwgUGFyc2UuRXJyb3IuU0NSSVBUX0ZBSUxFRDtcbiAgLy8gSWYgaXQncyBhbiBlcnJvciwgbWFyayBpdCBhcyBhIHNjcmlwdCBmYWlsZWRcbiAgaWYgKHR5cGVvZiBtZXNzYWdlID09PSAnc3RyaW5nJykge1xuICAgIHJldHVybiBuZXcgUGFyc2UuRXJyb3IoY29kZSwgbWVzc2FnZSk7XG4gIH1cbiAgY29uc3QgZXJyb3IgPSBuZXcgUGFyc2UuRXJyb3IoY29kZSwgbWVzc2FnZS5tZXNzYWdlIHx8IG1lc3NhZ2UpO1xuICBpZiAobWVzc2FnZSBpbnN0YW5jZW9mIEVycm9yKSB7XG4gICAgZXJyb3Iuc3RhY2sgPSBtZXNzYWdlLnN0YWNrO1xuICB9XG4gIHJldHVybiBlcnJvcjtcbn1cbmV4cG9ydCBmdW5jdGlvbiBtYXliZVJ1blZhbGlkYXRvcihyZXF1ZXN0LCBmdW5jdGlvbk5hbWUsIGF1dGgpIHtcbiAgY29uc3QgdGhlVmFsaWRhdG9yID0gZ2V0VmFsaWRhdG9yKGZ1bmN0aW9uTmFtZSwgUGFyc2UuYXBwbGljYXRpb25JZCk7XG4gIGlmICghdGhlVmFsaWRhdG9yKSB7XG4gICAgcmV0dXJuO1xuICB9XG4gIGlmICh0eXBlb2YgdGhlVmFsaWRhdG9yID09PSAnb2JqZWN0JyAmJiB0aGVWYWxpZGF0b3Iuc2tpcFdpdGhNYXN0ZXJLZXkgJiYgcmVxdWVzdC5tYXN0ZXIpIHtcbiAgICByZXF1ZXN0LnNraXBXaXRoTWFzdGVyS2V5ID0gdHJ1ZTtcbiAgfVxuICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKVxuICAgICAgLnRoZW4oKCkgPT4ge1xuICAgICAgICByZXR1cm4gdHlwZW9mIHRoZVZhbGlkYXRvciA9PT0gJ29iamVjdCdcbiAgICAgICAgICA/IGJ1aWx0SW5UcmlnZ2VyVmFsaWRhdG9yKHRoZVZhbGlkYXRvciwgcmVxdWVzdCwgYXV0aClcbiAgICAgICAgICA6IHRoZVZhbGlkYXRvcihyZXF1ZXN0KTtcbiAgICAgIH0pXG4gICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgIHJlc29sdmUoKTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goZSA9PiB7XG4gICAgICAgIGNvbnN0IGVycm9yID0gcmVzb2x2ZUVycm9yKGUsIHtcbiAgICAgICAgICBjb2RlOiBQYXJzZS5FcnJvci5WQUxJREFUSU9OX0VSUk9SLFxuICAgICAgICAgIG1lc3NhZ2U6ICdWYWxpZGF0aW9uIGZhaWxlZC4nLFxuICAgICAgICB9KTtcbiAgICAgICAgcmVqZWN0KGVycm9yKTtcbiAgICAgIH0pO1xuICB9KTtcbn1cbmFzeW5jIGZ1bmN0aW9uIGJ1aWx0SW5UcmlnZ2VyVmFsaWRhdG9yKG9wdGlvbnMsIHJlcXVlc3QsIGF1dGgpIHtcbiAgaWYgKHJlcXVlc3QubWFzdGVyICYmICFvcHRpb25zLnZhbGlkYXRlTWFzdGVyS2V5KSB7XG4gICAgcmV0dXJuO1xuICB9XG4gIGxldCByZXFVc2VyID0gcmVxdWVzdC51c2VyO1xuICBpZiAoXG4gICAgIXJlcVVzZXIgJiZcbiAgICByZXF1ZXN0Lm9iamVjdCAmJlxuICAgIHJlcXVlc3Qub2JqZWN0LmNsYXNzTmFtZSA9PT0gJ19Vc2VyJyAmJlxuICAgICFyZXF1ZXN0Lm9iamVjdC5leGlzdGVkKClcbiAgKSB7XG4gICAgcmVxVXNlciA9IHJlcXVlc3Qub2JqZWN0O1xuICB9XG4gIGlmIChcbiAgICAob3B0aW9ucy5yZXF1aXJlVXNlciB8fCBvcHRpb25zLnJlcXVpcmVBbnlVc2VyUm9sZXMgfHwgb3B0aW9ucy5yZXF1aXJlQWxsVXNlclJvbGVzKSAmJlxuICAgICFyZXFVc2VyXG4gICkge1xuICAgIHRocm93ICdWYWxpZGF0aW9uIGZhaWxlZC4gUGxlYXNlIGxvZ2luIHRvIGNvbnRpbnVlLic7XG4gIH1cbiAgaWYgKG9wdGlvbnMucmVxdWlyZU1hc3RlciAmJiAhcmVxdWVzdC5tYXN0ZXIpIHtcbiAgICB0aHJvdyAnVmFsaWRhdGlvbiBmYWlsZWQuIE1hc3RlciBrZXkgaXMgcmVxdWlyZWQgdG8gY29tcGxldGUgdGhpcyByZXF1ZXN0Lic7XG4gIH1cbiAgbGV0IHBhcmFtcyA9IHJlcXVlc3QucGFyYW1zIHx8IHt9O1xuICBpZiAocmVxdWVzdC5vYmplY3QpIHtcbiAgICBwYXJhbXMgPSByZXF1ZXN0Lm9iamVjdC50b0pTT04oKTtcbiAgfVxuICBjb25zdCByZXF1aXJlZFBhcmFtID0ga2V5ID0+IHtcbiAgICBjb25zdCB2YWx1ZSA9IHBhcmFtc1trZXldO1xuICAgIGlmICh2YWx1ZSA9PSBudWxsKSB7XG4gICAgICB0aHJvdyBgVmFsaWRhdGlvbiBmYWlsZWQuIFBsZWFzZSBzcGVjaWZ5IGRhdGEgZm9yICR7a2V5fS5gO1xuICAgIH1cbiAgfTtcblxuICBjb25zdCB2YWxpZGF0ZU9wdGlvbnMgPSBhc3luYyAob3B0LCBrZXksIHZhbCkgPT4ge1xuICAgIGxldCBvcHRzID0gb3B0Lm9wdGlvbnM7XG4gICAgaWYgKHR5cGVvZiBvcHRzID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICB0cnkge1xuICAgICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBvcHRzKHZhbCk7XG4gICAgICAgIGlmICghcmVzdWx0ICYmIHJlc3VsdCAhPSBudWxsKSB7XG4gICAgICAgICAgdGhyb3cgb3B0LmVycm9yIHx8IGBWYWxpZGF0aW9uIGZhaWxlZC4gSW52YWxpZCB2YWx1ZSBmb3IgJHtrZXl9LmA7XG4gICAgICAgIH1cbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKCFlKSB7XG4gICAgICAgICAgdGhyb3cgb3B0LmVycm9yIHx8IGBWYWxpZGF0aW9uIGZhaWxlZC4gSW52YWxpZCB2YWx1ZSBmb3IgJHtrZXl9LmA7XG4gICAgICAgIH1cblxuICAgICAgICB0aHJvdyBvcHQuZXJyb3IgfHwgZS5tZXNzYWdlIHx8IGU7XG4gICAgICB9XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGlmICghQXJyYXkuaXNBcnJheShvcHRzKSkge1xuICAgICAgb3B0cyA9IFtvcHQub3B0aW9uc107XG4gICAgfVxuXG4gICAgaWYgKCFvcHRzLmluY2x1ZGVzKHZhbCkpIHtcbiAgICAgIHRocm93IChcbiAgICAgICAgb3B0LmVycm9yIHx8IGBWYWxpZGF0aW9uIGZhaWxlZC4gSW52YWxpZCBvcHRpb24gZm9yICR7a2V5fS4gRXhwZWN0ZWQ6ICR7b3B0cy5qb2luKCcsICcpfWBcbiAgICAgICk7XG4gICAgfVxuICB9O1xuXG4gIGNvbnN0IGdldFR5cGUgPSBmbiA9PiB7XG4gICAgY29uc3QgbWF0Y2ggPSBmbiAmJiBmbi50b1N0cmluZygpLm1hdGNoKC9eXFxzKmZ1bmN0aW9uIChcXHcrKS8pO1xuICAgIHJldHVybiAobWF0Y2ggPyBtYXRjaFsxXSA6ICcnKS50b0xvd2VyQ2FzZSgpO1xuICB9O1xuICBpZiAoQXJyYXkuaXNBcnJheShvcHRpb25zLmZpZWxkcykpIHtcbiAgICBmb3IgKGNvbnN0IGtleSBvZiBvcHRpb25zLmZpZWxkcykge1xuICAgICAgcmVxdWlyZWRQYXJhbShrZXkpO1xuICAgIH1cbiAgfSBlbHNlIHtcbiAgICBjb25zdCBvcHRpb25Qcm9taXNlcyA9IFtdO1xuICAgIGZvciAoY29uc3Qga2V5IGluIG9wdGlvbnMuZmllbGRzKSB7XG4gICAgICBjb25zdCBvcHQgPSBvcHRpb25zLmZpZWxkc1trZXldO1xuICAgICAgbGV0IHZhbCA9IHBhcmFtc1trZXldO1xuICAgICAgaWYgKHR5cGVvZiBvcHQgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHJlcXVpcmVkUGFyYW0ob3B0KTtcbiAgICAgIH1cbiAgICAgIGlmICh0eXBlb2Ygb3B0ID09PSAnb2JqZWN0Jykge1xuICAgICAgICBpZiAob3B0LmRlZmF1bHQgIT0gbnVsbCAmJiB2YWwgPT0gbnVsbCkge1xuICAgICAgICAgIHZhbCA9IG9wdC5kZWZhdWx0O1xuICAgICAgICAgIHBhcmFtc1trZXldID0gdmFsO1xuICAgICAgICAgIGlmIChyZXF1ZXN0Lm9iamVjdCkge1xuICAgICAgICAgICAgcmVxdWVzdC5vYmplY3Quc2V0KGtleSwgdmFsKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgaWYgKG9wdC5jb25zdGFudCAmJiByZXF1ZXN0Lm9iamVjdCkge1xuICAgICAgICAgIGlmIChyZXF1ZXN0Lm9yaWdpbmFsKSB7XG4gICAgICAgICAgICByZXF1ZXN0Lm9iamVjdC5zZXQoa2V5LCByZXF1ZXN0Lm9yaWdpbmFsLmdldChrZXkpKTtcbiAgICAgICAgICB9IGVsc2UgaWYgKG9wdC5kZWZhdWx0ICE9IG51bGwpIHtcbiAgICAgICAgICAgIHJlcXVlc3Qub2JqZWN0LnNldChrZXksIG9wdC5kZWZhdWx0KTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgaWYgKG9wdC5yZXF1aXJlZCkge1xuICAgICAgICAgIHJlcXVpcmVkUGFyYW0oa2V5KTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBvcHRpb25hbCA9ICFvcHQucmVxdWlyZWQgJiYgdmFsID09PSB1bmRlZmluZWQ7XG4gICAgICAgIGlmICghb3B0aW9uYWwpIHtcbiAgICAgICAgICBpZiAob3B0LnR5cGUpIHtcbiAgICAgICAgICAgIGNvbnN0IHR5cGUgPSBnZXRUeXBlKG9wdC50eXBlKTtcbiAgICAgICAgICAgIGNvbnN0IHZhbFR5cGUgPSBBcnJheS5pc0FycmF5KHZhbCkgPyAnYXJyYXknIDogdHlwZW9mIHZhbDtcbiAgICAgICAgICAgIGlmICh2YWxUeXBlICE9PSB0eXBlKSB7XG4gICAgICAgICAgICAgIHRocm93IGBWYWxpZGF0aW9uIGZhaWxlZC4gSW52YWxpZCB0eXBlIGZvciAke2tleX0uIEV4cGVjdGVkOiAke3R5cGV9YDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgICAgaWYgKG9wdC5vcHRpb25zKSB7XG4gICAgICAgICAgICBvcHRpb25Qcm9taXNlcy5wdXNoKHZhbGlkYXRlT3B0aW9ucyhvcHQsIGtleSwgdmFsKSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIGF3YWl0IFByb21pc2UuYWxsKG9wdGlvblByb21pc2VzKTtcbiAgfVxuICBsZXQgdXNlclJvbGVzID0gb3B0aW9ucy5yZXF1aXJlQW55VXNlclJvbGVzO1xuICBsZXQgcmVxdWlyZUFsbFJvbGVzID0gb3B0aW9ucy5yZXF1aXJlQWxsVXNlclJvbGVzO1xuICBjb25zdCBwcm9taXNlcyA9IFtQcm9taXNlLnJlc29sdmUoKSwgUHJvbWlzZS5yZXNvbHZlKCksIFByb21pc2UucmVzb2x2ZSgpXTtcbiAgaWYgKHVzZXJSb2xlcyB8fCByZXF1aXJlQWxsUm9sZXMpIHtcbiAgICBwcm9taXNlc1swXSA9IGF1dGguZ2V0VXNlclJvbGVzKCk7XG4gIH1cbiAgaWYgKHR5cGVvZiB1c2VyUm9sZXMgPT09ICdmdW5jdGlvbicpIHtcbiAgICBwcm9taXNlc1sxXSA9IHVzZXJSb2xlcygpO1xuICB9XG4gIGlmICh0eXBlb2YgcmVxdWlyZUFsbFJvbGVzID09PSAnZnVuY3Rpb24nKSB7XG4gICAgcHJvbWlzZXNbMl0gPSByZXF1aXJlQWxsUm9sZXMoKTtcbiAgfVxuICBjb25zdCBbcm9sZXMsIHJlc29sdmVkVXNlclJvbGVzLCByZXNvbHZlZFJlcXVpcmVBbGxdID0gYXdhaXQgUHJvbWlzZS5hbGwocHJvbWlzZXMpO1xuICBpZiAocmVzb2x2ZWRVc2VyUm9sZXMgJiYgQXJyYXkuaXNBcnJheShyZXNvbHZlZFVzZXJSb2xlcykpIHtcbiAgICB1c2VyUm9sZXMgPSByZXNvbHZlZFVzZXJSb2xlcztcbiAgfVxuICBpZiAocmVzb2x2ZWRSZXF1aXJlQWxsICYmIEFycmF5LmlzQXJyYXkocmVzb2x2ZWRSZXF1aXJlQWxsKSkge1xuICAgIHJlcXVpcmVBbGxSb2xlcyA9IHJlc29sdmVkUmVxdWlyZUFsbDtcbiAgfVxuICBpZiAodXNlclJvbGVzKSB7XG4gICAgY29uc3QgaGFzUm9sZSA9IHVzZXJSb2xlcy5zb21lKHJlcXVpcmVkUm9sZSA9PiByb2xlcy5pbmNsdWRlcyhgcm9sZToke3JlcXVpcmVkUm9sZX1gKSk7XG4gICAgaWYgKCFoYXNSb2xlKSB7XG4gICAgICB0aHJvdyBgVmFsaWRhdGlvbiBmYWlsZWQuIFVzZXIgZG9lcyBub3QgbWF0Y2ggdGhlIHJlcXVpcmVkIHJvbGVzLmA7XG4gICAgfVxuICB9XG4gIGlmIChyZXF1aXJlQWxsUm9sZXMpIHtcbiAgICBmb3IgKGNvbnN0IHJlcXVpcmVkUm9sZSBvZiByZXF1aXJlQWxsUm9sZXMpIHtcbiAgICAgIGlmICghcm9sZXMuaW5jbHVkZXMoYHJvbGU6JHtyZXF1aXJlZFJvbGV9YCkpIHtcbiAgICAgICAgdGhyb3cgYFZhbGlkYXRpb24gZmFpbGVkLiBVc2VyIGRvZXMgbm90IG1hdGNoIGFsbCB0aGUgcmVxdWlyZWQgcm9sZXMuYDtcbiAgICAgIH1cbiAgICB9XG4gIH1cbiAgY29uc3QgdXNlcktleXMgPSBvcHRpb25zLnJlcXVpcmVVc2VyS2V5cyB8fCBbXTtcbiAgaWYgKEFycmF5LmlzQXJyYXkodXNlcktleXMpKSB7XG4gICAgZm9yIChjb25zdCBrZXkgb2YgdXNlcktleXMpIHtcbiAgICAgIGlmICghcmVxVXNlcikge1xuICAgICAgICB0aHJvdyAnUGxlYXNlIGxvZ2luIHRvIG1ha2UgdGhpcyByZXF1ZXN0Lic7XG4gICAgICB9XG5cbiAgICAgIGlmIChyZXFVc2VyLmdldChrZXkpID09IG51bGwpIHtcbiAgICAgICAgdGhyb3cgYFZhbGlkYXRpb24gZmFpbGVkLiBQbGVhc2Ugc2V0IGRhdGEgZm9yICR7a2V5fSBvbiB5b3VyIGFjY291bnQuYDtcbiAgICAgIH1cbiAgICB9XG4gIH0gZWxzZSBpZiAodHlwZW9mIHVzZXJLZXlzID09PSAnb2JqZWN0Jykge1xuICAgIGNvbnN0IG9wdGlvblByb21pc2VzID0gW107XG4gICAgZm9yIChjb25zdCBrZXkgaW4gb3B0aW9ucy5yZXF1aXJlVXNlcktleXMpIHtcbiAgICAgIGNvbnN0IG9wdCA9IG9wdGlvbnMucmVxdWlyZVVzZXJLZXlzW2tleV07XG4gICAgICBpZiAob3B0Lm9wdGlvbnMpIHtcbiAgICAgICAgb3B0aW9uUHJvbWlzZXMucHVzaCh2YWxpZGF0ZU9wdGlvbnMob3B0LCBrZXksIHJlcVVzZXIuZ2V0KGtleSkpKTtcbiAgICAgIH1cbiAgICB9XG4gICAgYXdhaXQgUHJvbWlzZS5hbGwob3B0aW9uUHJvbWlzZXMpO1xuICB9XG59XG5cbi8vIFRvIGJlIHVzZWQgYXMgcGFydCBvZiB0aGUgcHJvbWlzZSBjaGFpbiB3aGVuIHNhdmluZy9kZWxldGluZyBhbiBvYmplY3Rcbi8vIFdpbGwgcmVzb2x2ZSBzdWNjZXNzZnVsbHkgaWYgbm8gdHJpZ2dlciBpcyBjb25maWd1cmVkXG4vLyBSZXNvbHZlcyB0byBhbiBvYmplY3QsIGVtcHR5IG9yIGNvbnRhaW5pbmcgYW4gb2JqZWN0IGtleS4gQSBiZWZvcmVTYXZlXG4vLyB0cmlnZ2VyIHdpbGwgc2V0IHRoZSBvYmplY3Qga2V5IHRvIHRoZSByZXN0IGZvcm1hdCBvYmplY3QgdG8gc2F2ZS5cbi8vIG9yaWdpbmFsUGFyc2VPYmplY3QgaXMgb3B0aW9uYWwsIHdlIG9ubHkgbmVlZCB0aGF0IGZvciBiZWZvcmUvYWZ0ZXJTYXZlIGZ1bmN0aW9uc1xuZXhwb3J0IGZ1bmN0aW9uIG1heWJlUnVuVHJpZ2dlcihcbiAgdHJpZ2dlclR5cGUsXG4gIGF1dGgsXG4gIHBhcnNlT2JqZWN0LFxuICBvcmlnaW5hbFBhcnNlT2JqZWN0LFxuICBjb25maWcsXG4gIGNvbnRleHRcbikge1xuICBpZiAoIXBhcnNlT2JqZWN0KSB7XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh7fSk7XG4gIH1cbiAgcmV0dXJuIG5ldyBQcm9taXNlKGZ1bmN0aW9uIChyZXNvbHZlLCByZWplY3QpIHtcbiAgICB2YXIgdHJpZ2dlciA9IGdldFRyaWdnZXIocGFyc2VPYmplY3QuY2xhc3NOYW1lLCB0cmlnZ2VyVHlwZSwgY29uZmlnLmFwcGxpY2F0aW9uSWQpO1xuICAgIGlmICghdHJpZ2dlcikgcmV0dXJuIHJlc29sdmUoKTtcbiAgICB2YXIgcmVxdWVzdCA9IGdldFJlcXVlc3RPYmplY3QoXG4gICAgICB0cmlnZ2VyVHlwZSxcbiAgICAgIGF1dGgsXG4gICAgICBwYXJzZU9iamVjdCxcbiAgICAgIG9yaWdpbmFsUGFyc2VPYmplY3QsXG4gICAgICBjb25maWcsXG4gICAgICBjb250ZXh0XG4gICAgKTtcbiAgICB2YXIgeyBzdWNjZXNzLCBlcnJvciB9ID0gZ2V0UmVzcG9uc2VPYmplY3QoXG4gICAgICByZXF1ZXN0LFxuICAgICAgb2JqZWN0ID0+IHtcbiAgICAgICAgbG9nVHJpZ2dlclN1Y2Nlc3NCZWZvcmVIb29rKFxuICAgICAgICAgIHRyaWdnZXJUeXBlLFxuICAgICAgICAgIHBhcnNlT2JqZWN0LmNsYXNzTmFtZSxcbiAgICAgICAgICBwYXJzZU9iamVjdC50b0pTT04oKSxcbiAgICAgICAgICBvYmplY3QsXG4gICAgICAgICAgYXV0aFxuICAgICAgICApO1xuICAgICAgICBpZiAoXG4gICAgICAgICAgdHJpZ2dlclR5cGUgPT09IFR5cGVzLmJlZm9yZVNhdmUgfHxcbiAgICAgICAgICB0cmlnZ2VyVHlwZSA9PT0gVHlwZXMuYWZ0ZXJTYXZlIHx8XG4gICAgICAgICAgdHJpZ2dlclR5cGUgPT09IFR5cGVzLmJlZm9yZURlbGV0ZSB8fFxuICAgICAgICAgIHRyaWdnZXJUeXBlID09PSBUeXBlcy5hZnRlckRlbGV0ZVxuICAgICAgICApIHtcbiAgICAgICAgICBPYmplY3QuYXNzaWduKGNvbnRleHQsIHJlcXVlc3QuY29udGV4dCk7XG4gICAgICAgIH1cbiAgICAgICAgcmVzb2x2ZShvYmplY3QpO1xuICAgICAgfSxcbiAgICAgIGVycm9yID0+IHtcbiAgICAgICAgbG9nVHJpZ2dlckVycm9yQmVmb3JlSG9vayhcbiAgICAgICAgICB0cmlnZ2VyVHlwZSxcbiAgICAgICAgICBwYXJzZU9iamVjdC5jbGFzc05hbWUsXG4gICAgICAgICAgcGFyc2VPYmplY3QudG9KU09OKCksXG4gICAgICAgICAgYXV0aCxcbiAgICAgICAgICBlcnJvclxuICAgICAgICApO1xuICAgICAgICByZWplY3QoZXJyb3IpO1xuICAgICAgfVxuICAgICk7XG5cbiAgICAvLyBBZnRlclNhdmUgYW5kIGFmdGVyRGVsZXRlIHRyaWdnZXJzIGNhbiByZXR1cm4gYSBwcm9taXNlLCB3aGljaCBpZiB0aGV5XG4gICAgLy8gZG8sIG5lZWRzIHRvIGJlIHJlc29sdmVkIGJlZm9yZSB0aGlzIHByb21pc2UgaXMgcmVzb2x2ZWQsXG4gICAgLy8gc28gdHJpZ2dlciBleGVjdXRpb24gaXMgc3luY2VkIHdpdGggUmVzdFdyaXRlLmV4ZWN1dGUoKSBjYWxsLlxuICAgIC8vIElmIHRyaWdnZXJzIGRvIG5vdCByZXR1cm4gYSBwcm9taXNlLCB0aGV5IGNhbiBydW4gYXN5bmMgY29kZSBwYXJhbGxlbFxuICAgIC8vIHRvIHRoZSBSZXN0V3JpdGUuZXhlY3V0ZSgpIGNhbGwuXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpXG4gICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgIHJldHVybiBtYXliZVJ1blZhbGlkYXRvcihyZXF1ZXN0LCBgJHt0cmlnZ2VyVHlwZX0uJHtwYXJzZU9iamVjdC5jbGFzc05hbWV9YCwgYXV0aCk7XG4gICAgICB9KVxuICAgICAgLnRoZW4oKCkgPT4ge1xuICAgICAgICBpZiAocmVxdWVzdC5za2lwV2l0aE1hc3RlcktleSkge1xuICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBwcm9taXNlID0gdHJpZ2dlcihyZXF1ZXN0KTtcbiAgICAgICAgaWYgKFxuICAgICAgICAgIHRyaWdnZXJUeXBlID09PSBUeXBlcy5hZnRlclNhdmUgfHxcbiAgICAgICAgICB0cmlnZ2VyVHlwZSA9PT0gVHlwZXMuYWZ0ZXJEZWxldGUgfHxcbiAgICAgICAgICB0cmlnZ2VyVHlwZSA9PT0gVHlwZXMuYWZ0ZXJMb2dpblxuICAgICAgICApIHtcbiAgICAgICAgICBsb2dUcmlnZ2VyQWZ0ZXJIb29rKHRyaWdnZXJUeXBlLCBwYXJzZU9iamVjdC5jbGFzc05hbWUsIHBhcnNlT2JqZWN0LnRvSlNPTigpLCBhdXRoKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBiZWZvcmVTYXZlIGlzIGV4cGVjdGVkIHRvIHJldHVybiBudWxsIChub3RoaW5nKVxuICAgICAgICBpZiAodHJpZ2dlclR5cGUgPT09IFR5cGVzLmJlZm9yZVNhdmUpIHtcbiAgICAgICAgICBpZiAocHJvbWlzZSAmJiB0eXBlb2YgcHJvbWlzZS50aGVuID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICByZXR1cm4gcHJvbWlzZS50aGVuKHJlc3BvbnNlID0+IHtcbiAgICAgICAgICAgICAgLy8gcmVzcG9uc2Uub2JqZWN0IG1heSBjb21lIGZyb20gZXhwcmVzcyByb3V0aW5nIGJlZm9yZSBob29rXG4gICAgICAgICAgICAgIGlmIChyZXNwb25zZSAmJiByZXNwb25zZS5vYmplY3QpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gcmVzcG9uc2U7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gcHJvbWlzZTtcbiAgICAgIH0pXG4gICAgICAudGhlbihzdWNjZXNzLCBlcnJvcik7XG4gIH0pO1xufVxuXG4vLyBDb252ZXJ0cyBhIFJFU1QtZm9ybWF0IG9iamVjdCB0byBhIFBhcnNlLk9iamVjdFxuLy8gZGF0YSBpcyBlaXRoZXIgY2xhc3NOYW1lIG9yIGFuIG9iamVjdFxuZXhwb3J0IGZ1bmN0aW9uIGluZmxhdGUoZGF0YSwgcmVzdE9iamVjdCkge1xuICB2YXIgY29weSA9IHR5cGVvZiBkYXRhID09ICdvYmplY3QnID8gZGF0YSA6IHsgY2xhc3NOYW1lOiBkYXRhIH07XG4gIGZvciAodmFyIGtleSBpbiByZXN0T2JqZWN0KSB7XG4gICAgY29weVtrZXldID0gcmVzdE9iamVjdFtrZXldO1xuICB9XG4gIHJldHVybiBQYXJzZS5PYmplY3QuZnJvbUpTT04oY29weSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBydW5MaXZlUXVlcnlFdmVudEhhbmRsZXJzKGRhdGEsIGFwcGxpY2F0aW9uSWQgPSBQYXJzZS5hcHBsaWNhdGlvbklkKSB7XG4gIGlmICghX3RyaWdnZXJTdG9yZSB8fCAhX3RyaWdnZXJTdG9yZVthcHBsaWNhdGlvbklkXSB8fCAhX3RyaWdnZXJTdG9yZVthcHBsaWNhdGlvbklkXS5MaXZlUXVlcnkpIHtcbiAgICByZXR1cm47XG4gIH1cbiAgX3RyaWdnZXJTdG9yZVthcHBsaWNhdGlvbklkXS5MaXZlUXVlcnkuZm9yRWFjaChoYW5kbGVyID0+IGhhbmRsZXIoZGF0YSkpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2V0UmVxdWVzdEZpbGVPYmplY3QodHJpZ2dlclR5cGUsIGF1dGgsIGZpbGVPYmplY3QsIGNvbmZpZykge1xuICBjb25zdCByZXF1ZXN0ID0ge1xuICAgIC4uLmZpbGVPYmplY3QsXG4gICAgdHJpZ2dlck5hbWU6IHRyaWdnZXJUeXBlLFxuICAgIG1hc3RlcjogZmFsc2UsXG4gICAgbG9nOiBjb25maWcubG9nZ2VyQ29udHJvbGxlcixcbiAgICBoZWFkZXJzOiBjb25maWcuaGVhZGVycyxcbiAgICBpcDogY29uZmlnLmlwLFxuICB9O1xuXG4gIGlmICghYXV0aCkge1xuICAgIHJldHVybiByZXF1ZXN0O1xuICB9XG4gIGlmIChhdXRoLmlzTWFzdGVyKSB7XG4gICAgcmVxdWVzdFsnbWFzdGVyJ10gPSB0cnVlO1xuICB9XG4gIGlmIChhdXRoLnVzZXIpIHtcbiAgICByZXF1ZXN0Wyd1c2VyJ10gPSBhdXRoLnVzZXI7XG4gIH1cbiAgaWYgKGF1dGguaW5zdGFsbGF0aW9uSWQpIHtcbiAgICByZXF1ZXN0WydpbnN0YWxsYXRpb25JZCddID0gYXV0aC5pbnN0YWxsYXRpb25JZDtcbiAgfVxuICByZXR1cm4gcmVxdWVzdDtcbn1cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIG1heWJlUnVuRmlsZVRyaWdnZXIodHJpZ2dlclR5cGUsIGZpbGVPYmplY3QsIGNvbmZpZywgYXV0aCkge1xuICBjb25zdCBmaWxlVHJpZ2dlciA9IGdldEZpbGVUcmlnZ2VyKHRyaWdnZXJUeXBlLCBjb25maWcuYXBwbGljYXRpb25JZCk7XG4gIGlmICh0eXBlb2YgZmlsZVRyaWdnZXIgPT09ICdmdW5jdGlvbicpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcmVxdWVzdCA9IGdldFJlcXVlc3RGaWxlT2JqZWN0KHRyaWdnZXJUeXBlLCBhdXRoLCBmaWxlT2JqZWN0LCBjb25maWcpO1xuICAgICAgYXdhaXQgbWF5YmVSdW5WYWxpZGF0b3IocmVxdWVzdCwgYCR7dHJpZ2dlclR5cGV9LiR7RmlsZUNsYXNzTmFtZX1gLCBhdXRoKTtcbiAgICAgIGlmIChyZXF1ZXN0LnNraXBXaXRoTWFzdGVyS2V5KSB7XG4gICAgICAgIHJldHVybiBmaWxlT2JqZWN0O1xuICAgICAgfVxuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgZmlsZVRyaWdnZXIocmVxdWVzdCk7XG4gICAgICBsb2dUcmlnZ2VyU3VjY2Vzc0JlZm9yZUhvb2soXG4gICAgICAgIHRyaWdnZXJUeXBlLFxuICAgICAgICAnUGFyc2UuRmlsZScsXG4gICAgICAgIHsgLi4uZmlsZU9iamVjdC5maWxlLnRvSlNPTigpLCBmaWxlU2l6ZTogZmlsZU9iamVjdC5maWxlU2l6ZSB9LFxuICAgICAgICByZXN1bHQsXG4gICAgICAgIGF1dGhcbiAgICAgICk7XG4gICAgICByZXR1cm4gcmVzdWx0IHx8IGZpbGVPYmplY3Q7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZ1RyaWdnZXJFcnJvckJlZm9yZUhvb2soXG4gICAgICAgIHRyaWdnZXJUeXBlLFxuICAgICAgICAnUGFyc2UuRmlsZScsXG4gICAgICAgIHsgLi4uZmlsZU9iamVjdC5maWxlLnRvSlNPTigpLCBmaWxlU2l6ZTogZmlsZU9iamVjdC5maWxlU2l6ZSB9LFxuICAgICAgICBhdXRoLFxuICAgICAgICBlcnJvclxuICAgICAgKTtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgfVxuICByZXR1cm4gZmlsZU9iamVjdDtcbn1cbiJdfQ==