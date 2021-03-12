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
exports.maybeRunConnectTrigger = maybeRunConnectTrigger;
exports.maybeRunSubscribeTrigger = maybeRunSubscribeTrigger;
exports.maybeRunAfterEventTrigger = maybeRunAfterEventTrigger;
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
      return maybeRunValidator(request, `${triggerType}.${className}`);
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
    return maybeRunValidator(requestObject, `${triggerType}.${className}`);
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

function maybeRunValidator(request, functionName) {
  const theValidator = getValidator(functionName, _node.default.applicationId);

  if (!theValidator) {
    return;
  }

  if (typeof theValidator === 'object' && theValidator.skipWithMasterKey && request.master) {
    request.skipWithMasterKey = true;
  }

  return new Promise((resolve, reject) => {
    return Promise.resolve().then(() => {
      return typeof theValidator === 'object' ? builtInTriggerValidator(theValidator, request) : theValidator(request);
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

function builtInTriggerValidator(options, request) {
  if (request.master && !options.validateMasterKey) {
    return;
  }

  let reqUser = request.user;

  if (!reqUser && request.object && request.object.className === '_User' && !request.object.existed()) {
    reqUser = request.object;
  }

  if (options.requireUser && !reqUser) {
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

  const validateOptions = (opt, key, val) => {
    let opts = opt.options;

    if (typeof opts === 'function') {
      try {
        const result = opts(val);

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

        if (opt.type) {
          const type = getType(opt.type);

          if (type == 'array' && !Array.isArray(val)) {
            throw `Validation failed. Invalid type for ${key}. Expected: array`;
          } else if (typeof val !== type) {
            throw `Validation failed. Invalid type for ${key}. Expected: ${type}`;
          }
        }

        if (opt.options) {
          validateOptions(opt, key, val);
        }
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
    for (const key in options.requireUserKeys) {
      const opt = options.requireUserKeys[key];

      if (opt.options) {
        validateOptions(opt, key, reqUser.get(key));
      }
    }
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
      return maybeRunValidator(request, `${triggerType}.${parseObject.className}`);
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
      await maybeRunValidator(request, `${triggerType}.${FileClassName}`);

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

async function maybeRunConnectTrigger(triggerType, request) {
  const trigger = getTrigger(ConnectClassName, triggerType, _node.default.applicationId);

  if (!trigger) {
    return;
  }

  request.user = await userForSessionToken(request.sessionToken);
  await maybeRunValidator(request, `${triggerType}.${ConnectClassName}`);

  if (request.skipWithMasterKey) {
    return;
  }

  return trigger(request);
}

async function maybeRunSubscribeTrigger(triggerType, className, request) {
  const trigger = getTrigger(className, triggerType, _node.default.applicationId);

  if (!trigger) {
    return;
  }

  const parseQuery = new _node.default.Query(className);
  parseQuery.withJSON(request.query);
  request.query = parseQuery;
  request.user = await userForSessionToken(request.sessionToken);
  await maybeRunValidator(request, `${triggerType}.${className}`);

  if (request.skipWithMasterKey) {
    return;
  }

  await trigger(request);
  const query = request.query.toJSON();

  if (query.keys) {
    query.fields = query.keys.split(',');
  }

  request.query = query;
}

async function maybeRunAfterEventTrigger(triggerType, className, request) {
  const trigger = getTrigger(className, triggerType, _node.default.applicationId);

  if (!trigger) {
    return;
  }

  if (request.object) {
    request.object = _node.default.Object.fromJSON(request.object);
  }

  if (request.original) {
    request.original = _node.default.Object.fromJSON(request.original);
  }

  request.user = await userForSessionToken(request.sessionToken);
  await maybeRunValidator(request, `${triggerType}.${className}`);

  if (request.skipWithMasterKey) {
    return;
  }

  return trigger(request);
}

async function userForSessionToken(sessionToken) {
  if (!sessionToken) {
    return;
  }

  const q = new _node.default.Query('_Session');
  q.equalTo('sessionToken', sessionToken);
  q.include('user');
  const session = await q.first({
    useMasterKey: true
  });

  if (!session) {
    return;
  }

  return session.get('user');
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy90cmlnZ2Vycy5qcyJdLCJuYW1lcyI6WyJUeXBlcyIsImJlZm9yZUxvZ2luIiwiYWZ0ZXJMb2dpbiIsImFmdGVyTG9nb3V0IiwiYmVmb3JlU2F2ZSIsImFmdGVyU2F2ZSIsImJlZm9yZURlbGV0ZSIsImFmdGVyRGVsZXRlIiwiYmVmb3JlRmluZCIsImFmdGVyRmluZCIsImJlZm9yZVNhdmVGaWxlIiwiYWZ0ZXJTYXZlRmlsZSIsImJlZm9yZURlbGV0ZUZpbGUiLCJhZnRlckRlbGV0ZUZpbGUiLCJiZWZvcmVDb25uZWN0IiwiYmVmb3JlU3Vic2NyaWJlIiwiYWZ0ZXJFdmVudCIsIkZpbGVDbGFzc05hbWUiLCJDb25uZWN0Q2xhc3NOYW1lIiwiYmFzZVN0b3JlIiwiVmFsaWRhdG9ycyIsIk9iamVjdCIsImtleXMiLCJyZWR1Y2UiLCJiYXNlIiwia2V5IiwiRnVuY3Rpb25zIiwiSm9icyIsIkxpdmVRdWVyeSIsIlRyaWdnZXJzIiwiZnJlZXplIiwidmFsaWRhdGVDbGFzc05hbWVGb3JUcmlnZ2VycyIsImNsYXNzTmFtZSIsInR5cGUiLCJfdHJpZ2dlclN0b3JlIiwiQ2F0ZWdvcnkiLCJnZXRTdG9yZSIsImNhdGVnb3J5IiwibmFtZSIsImFwcGxpY2F0aW9uSWQiLCJwYXRoIiwic3BsaXQiLCJzcGxpY2UiLCJQYXJzZSIsInN0b3JlIiwiY29tcG9uZW50IiwidW5kZWZpbmVkIiwiYWRkIiwiaGFuZGxlciIsImxhc3RDb21wb25lbnQiLCJsb2dnZXIiLCJ3YXJuIiwicmVtb3ZlIiwiZ2V0IiwiYWRkRnVuY3Rpb24iLCJmdW5jdGlvbk5hbWUiLCJ2YWxpZGF0aW9uSGFuZGxlciIsImFkZEpvYiIsImpvYk5hbWUiLCJhZGRUcmlnZ2VyIiwiYWRkRmlsZVRyaWdnZXIiLCJhZGRDb25uZWN0VHJpZ2dlciIsImFkZExpdmVRdWVyeUV2ZW50SGFuZGxlciIsInB1c2giLCJyZW1vdmVGdW5jdGlvbiIsInJlbW92ZVRyaWdnZXIiLCJfdW5yZWdpc3RlckFsbCIsImZvckVhY2giLCJhcHBJZCIsImdldFRyaWdnZXIiLCJ0cmlnZ2VyVHlwZSIsImdldEZpbGVUcmlnZ2VyIiwidHJpZ2dlckV4aXN0cyIsImdldEZ1bmN0aW9uIiwiZ2V0RnVuY3Rpb25OYW1lcyIsImZ1bmN0aW9uTmFtZXMiLCJleHRyYWN0RnVuY3Rpb25OYW1lcyIsIm5hbWVzcGFjZSIsInZhbHVlIiwiZ2V0Sm9iIiwiZ2V0Sm9icyIsIm1hbmFnZXIiLCJnZXRWYWxpZGF0b3IiLCJnZXRSZXF1ZXN0T2JqZWN0IiwiYXV0aCIsInBhcnNlT2JqZWN0Iiwib3JpZ2luYWxQYXJzZU9iamVjdCIsImNvbmZpZyIsImNvbnRleHQiLCJyZXF1ZXN0IiwidHJpZ2dlck5hbWUiLCJvYmplY3QiLCJtYXN0ZXIiLCJsb2ciLCJsb2dnZXJDb250cm9sbGVyIiwiaGVhZGVycyIsImlwIiwib3JpZ2luYWwiLCJhc3NpZ24iLCJpc01hc3RlciIsInVzZXIiLCJpbnN0YWxsYXRpb25JZCIsImdldFJlcXVlc3RRdWVyeU9iamVjdCIsInF1ZXJ5IiwiY291bnQiLCJpc0dldCIsImdldFJlc3BvbnNlT2JqZWN0IiwicmVzb2x2ZSIsInJlamVjdCIsInN1Y2Nlc3MiLCJyZXNwb25zZSIsIm9iamVjdHMiLCJtYXAiLCJ0b0pTT04iLCJlcXVhbHMiLCJfZ2V0U2F2ZUpTT04iLCJpZCIsImVycm9yIiwiZSIsInJlc29sdmVFcnJvciIsImNvZGUiLCJFcnJvciIsIlNDUklQVF9GQUlMRUQiLCJtZXNzYWdlIiwidXNlcklkRm9yTG9nIiwibG9nVHJpZ2dlckFmdGVySG9vayIsImlucHV0IiwiY2xlYW5JbnB1dCIsInRydW5jYXRlTG9nTWVzc2FnZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJpbmZvIiwibG9nVHJpZ2dlclN1Y2Nlc3NCZWZvcmVIb29rIiwicmVzdWx0IiwiY2xlYW5SZXN1bHQiLCJsb2dUcmlnZ2VyRXJyb3JCZWZvcmVIb29rIiwibWF5YmVSdW5BZnRlckZpbmRUcmlnZ2VyIiwiUHJvbWlzZSIsInRyaWdnZXIiLCJmcm9tSlNPTiIsInRoZW4iLCJtYXliZVJ1blZhbGlkYXRvciIsInNraXBXaXRoTWFzdGVyS2V5IiwicmVzdWx0cyIsIm1heWJlUnVuUXVlcnlUcmlnZ2VyIiwicmVzdFdoZXJlIiwicmVzdE9wdGlvbnMiLCJqc29uIiwid2hlcmUiLCJwYXJzZVF1ZXJ5IiwiUXVlcnkiLCJ3aXRoSlNPTiIsInJlcXVlc3RPYmplY3QiLCJxdWVyeVJlc3VsdCIsImpzb25RdWVyeSIsImxpbWl0Iiwic2tpcCIsImluY2x1ZGUiLCJleGNsdWRlS2V5cyIsImV4cGxhaW4iLCJvcmRlciIsImhpbnQiLCJyZWFkUHJlZmVyZW5jZSIsImluY2x1ZGVSZWFkUHJlZmVyZW5jZSIsInN1YnF1ZXJ5UmVhZFByZWZlcmVuY2UiLCJlcnIiLCJkZWZhdWx0T3B0cyIsInN0YWNrIiwidGhlVmFsaWRhdG9yIiwiYnVpbHRJblRyaWdnZXJWYWxpZGF0b3IiLCJjYXRjaCIsIlZBTElEQVRJT05fRVJST1IiLCJvcHRpb25zIiwidmFsaWRhdGVNYXN0ZXJLZXkiLCJyZXFVc2VyIiwiZXhpc3RlZCIsInJlcXVpcmVVc2VyIiwicmVxdWlyZU1hc3RlciIsInBhcmFtcyIsInJlcXVpcmVkUGFyYW0iLCJ2YWxpZGF0ZU9wdGlvbnMiLCJvcHQiLCJ2YWwiLCJvcHRzIiwiQXJyYXkiLCJpc0FycmF5IiwiaW5jbHVkZXMiLCJqb2luIiwiZ2V0VHlwZSIsImZuIiwibWF0Y2giLCJ0b1N0cmluZyIsInRvTG93ZXJDYXNlIiwiZmllbGRzIiwiZGVmYXVsdCIsInNldCIsImNvbnN0YW50IiwicmVxdWlyZWQiLCJ1c2VyS2V5cyIsInJlcXVpcmVVc2VyS2V5cyIsIm1heWJlUnVuVHJpZ2dlciIsInByb21pc2UiLCJpbmZsYXRlIiwiZGF0YSIsInJlc3RPYmplY3QiLCJjb3B5IiwicnVuTGl2ZVF1ZXJ5RXZlbnRIYW5kbGVycyIsImdldFJlcXVlc3RGaWxlT2JqZWN0IiwiZmlsZU9iamVjdCIsIm1heWJlUnVuRmlsZVRyaWdnZXIiLCJmaWxlVHJpZ2dlciIsImZpbGUiLCJmaWxlU2l6ZSIsIm1heWJlUnVuQ29ubmVjdFRyaWdnZXIiLCJ1c2VyRm9yU2Vzc2lvblRva2VuIiwic2Vzc2lvblRva2VuIiwibWF5YmVSdW5TdWJzY3JpYmVUcmlnZ2VyIiwibWF5YmVSdW5BZnRlckV2ZW50VHJpZ2dlciIsInEiLCJlcXVhbFRvIiwic2Vzc2lvbiIsImZpcnN0IiwidXNlTWFzdGVyS2V5Il0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUFDQTs7QUFDQTs7Ozs7Ozs7OztBQUVPLE1BQU1BLEtBQUssR0FBRztBQUNuQkMsRUFBQUEsV0FBVyxFQUFFLGFBRE07QUFFbkJDLEVBQUFBLFVBQVUsRUFBRSxZQUZPO0FBR25CQyxFQUFBQSxXQUFXLEVBQUUsYUFITTtBQUluQkMsRUFBQUEsVUFBVSxFQUFFLFlBSk87QUFLbkJDLEVBQUFBLFNBQVMsRUFBRSxXQUxRO0FBTW5CQyxFQUFBQSxZQUFZLEVBQUUsY0FOSztBQU9uQkMsRUFBQUEsV0FBVyxFQUFFLGFBUE07QUFRbkJDLEVBQUFBLFVBQVUsRUFBRSxZQVJPO0FBU25CQyxFQUFBQSxTQUFTLEVBQUUsV0FUUTtBQVVuQkMsRUFBQUEsY0FBYyxFQUFFLGdCQVZHO0FBV25CQyxFQUFBQSxhQUFhLEVBQUUsZUFYSTtBQVluQkMsRUFBQUEsZ0JBQWdCLEVBQUUsa0JBWkM7QUFhbkJDLEVBQUFBLGVBQWUsRUFBRSxpQkFiRTtBQWNuQkMsRUFBQUEsYUFBYSxFQUFFLGVBZEk7QUFlbkJDLEVBQUFBLGVBQWUsRUFBRSxpQkFmRTtBQWdCbkJDLEVBQUFBLFVBQVUsRUFBRTtBQWhCTyxDQUFkOztBQW1CUCxNQUFNQyxhQUFhLEdBQUcsT0FBdEI7QUFDQSxNQUFNQyxnQkFBZ0IsR0FBRyxVQUF6Qjs7QUFFQSxNQUFNQyxTQUFTLEdBQUcsWUFBWTtBQUM1QixRQUFNQyxVQUFVLEdBQUdDLE1BQU0sQ0FBQ0MsSUFBUCxDQUFZdEIsS0FBWixFQUFtQnVCLE1BQW5CLENBQTBCLFVBQVVDLElBQVYsRUFB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RUFBYztBQUNaO0FBQ0Q7O0FBQ0QsU0FBT0EsT0FBTyxDQUFDdkssR0FBUixDQUFZLE1BQVosQ0FBUDtBQUNEIiwic291cmNlc0NvbnRlbnQiOlsiLy8gdHJpZ2dlcnMuanNcbmltcG9ydCBQYXJzZSBmcm9tICdwYXJzZS9ub2RlJztcbmltcG9ydCB7IGxvZ2dlciB9IGZyb20gJy4vbG9nZ2VyJztcblxuZXhwb3J0IGNvbnN0IFR5cGVzID0ge1xuICBiZWZvcmVMb2dpbjogJ2JlZm9yZUxvZ2luJyxcbiAgYWZ0ZXJMb2dpbjogJ2FmdGVyTG9naW4nLFxuICBhZnRlckxvZ291dDogJ2FmdGVyTG9nb3V0JyxcbiAgYmVmb3JlU2F2ZTogJ2JlZm9yZVNhdmUnLFxuICBhZnRlclNhdmU6ICdhZnRlclNhdmUnLFxuICBiZWZvcmVEZWxldGU6ICdiZWZvcmVEZWxldGUnLFxuICBhZnRlckRlbGV0ZTogJ2FmdGVyRGVsZXRlJyxcbiAgYmVmb3JlRmluZDogJ2JlZm9yZUZpbmQnLFxuICBhZnRlckZpbmQ6ICdhZnRlckZpbmQnLFxuICBiZWZvcmVTYXZlRmlsZTogJ2JlZm9yZVNhdmVGaWxlJyxcbiAgYWZ0ZXJTYXZlRmlsZTogJ2FmdGVyU2F2ZUZpbGUnLFxuICBiZWZvcmVEZWxldGVGaWxlOiAnYmVmb3JlRGVsZXRlRmlsZScsXG4gIGFmdGVyRGVsZXRlRmlsZTogJ2FmdGVyRGVsZXRlRmlsZScsXG4gIGJlZm9yZUNvbm5lY3Q6ICdiZWZvcmVDb25uZWN0JyxcbiAgYmVmb3JlU3Vic2NyaWJlOiAnYmVmb3JlU3Vic2NyaWJlJyxcbiAgYWZ0ZXJFdmVudDogJ2FmdGVyRXZlbnQnLFxufTtcblxuY29uc3QgRmlsZUNsYXNzTmFtZSA9ICdARmlsZSc7XG5jb25zdCBDb25uZWN0Q2xhc3NOYW1lID0gJ0BDb25uZWN0JztcblxuY29uc3QgYmFzZVN0b3JlID0gZnVuY3Rpb24gKCkge1xuICBjb25zdCBWYWxpZGF0b3JzID0gT2JqZWN0LmtleXMoVHlwZXMpLnJlZHVjZShmdW5jdGlvbiAoYmFzZSwga2V5KSB7XG4gICAgYmFzZVtrZXldID0ge307XG4gICAgcmV0dXJuIGJhc2U7XG4gIH0sIHt9KTtcbiAgY29uc3QgRnVuY3Rpb25zID0ge307XG4gIGNvbnN0IEpvYnMgPSB7fTtcbiAgY29uc3QgTGl2ZVF1ZXJ5ID0gW107XG4gIGNvbnN0IFRyaWdnZXJzID0gT2JqZWN0LmtleXMoVHlwZXMpLnJlZHVjZShmdW5jdGlvbiAoYmFzZSwga2V5KSB7XG4gICAgYmFzZVtrZXldID0ge307XG4gICAgcmV0dXJuIGJhc2U7XG4gIH0sIHt9KTtcblxuICByZXR1cm4gT2JqZWN0LmZyZWV6ZSh7XG4gICAgRnVuY3Rpb25zLFxuICAgIEpvYnMsXG4gICAgVmFsaWRhdG9ycyxcbiAgICBUcmlnZ2VycyxcbiAgICBMaXZlUXVlcnksXG4gIH0pO1xufTtcblxuZnVuY3Rpb24gdmFsaWRhdGVDbGFzc05hbWVGb3JUcmlnZ2VycyhjbGFzc05hbWUsIHR5cGUpIHtcbiAgaWYgKHR5cGUgPT0gVHlwZXMuYmVmb3JlU2F2ZSAmJiBjbGFzc05hbWUgPT09ICdfUHVzaFN0YXR1cycpIHtcbiAgICAvLyBfUHVzaFN0YXR1cyB1c2VzIHVuZG9jdW1lbnRlZCBuZXN0ZWQga2V5IGluY3JlbWVudCBvcHNcbiAgICAvLyBhbGxvd2luZyBiZWZvcmVTYXZlIHdvdWxkIG1lc3MgdXAgdGhlIG9iamVjdHMgYmlnIHRpbWVcbiAgICAvLyBUT0RPOiBBbGxvdyBwcm9wZXIgZG9jdW1lbnRlZCB3YXkgb2YgdXNpbmcgbmVzdGVkIGluY3JlbWVudCBvcHNcbiAgICB0aHJvdyAnT25seSBhZnRlclNhdmUgaXMgYWxsb3dlZCBvbiBfUHVzaFN0YXR1cyc7XG4gIH1cbiAgaWYgKCh0eXBlID09PSBUeXBlcy5iZWZvcmVMb2dpbiB8fCB0eXBlID09PSBUeXBlcy5hZnRlckxvZ2luKSAmJiBjbGFzc05hbWUgIT09ICdfVXNlcicpIHtcbiAgICAvLyBUT0RPOiBjaGVjayBpZiB1cHN0cmVhbSBjb2RlIHdpbGwgaGFuZGxlIGBFcnJvcmAgaW5zdGFuY2UgcmF0aGVyXG4gICAgLy8gdGhhbiB0aGlzIGFudGktcGF0dGVybiBvZiB0aHJvd2luZyBzdHJpbmdzXG4gICAgdGhyb3cgJ09ubHkgdGhlIF9Vc2VyIGNsYXNzIGlzIGFsbG93ZWQgZm9yIHRoZSBiZWZvcmVMb2dpbiBhbmQgYWZ0ZXJMb2dpbiB0cmlnZ2Vycyc7XG4gIH1cbiAgaWYgKHR5cGUgPT09IFR5cGVzLmFmdGVyTG9nb3V0ICYmIGNsYXNzTmFtZSAhPT0gJ19TZXNzaW9uJykge1xuICAgIC8vIFRPRE86IGNoZWNrIGlmIHVwc3RyZWFtIGNvZGUgd2lsbCBoYW5kbGUgYEVycm9yYCBpbnN0YW5jZSByYXRoZXJcbiAgICAvLyB0aGFuIHRoaXMgYW50aS1wYXR0ZXJuIG9mIHRocm93aW5nIHN0cmluZ3NcbiAgICB0aHJvdyAnT25seSB0aGUgX1Nlc3Npb24gY2xhc3MgaXMgYWxsb3dlZCBmb3IgdGhlIGFmdGVyTG9nb3V0IHRyaWdnZXIuJztcbiAgfVxuICBpZiAoY2xhc3NOYW1lID09PSAnX1Nlc3Npb24nICYmIHR5cGUgIT09IFR5cGVzLmFmdGVyTG9nb3V0KSB7XG4gICAgLy8gVE9ETzogY2hlY2sgaWYgdXBzdHJlYW0gY29kZSB3aWxsIGhhbmRsZSBgRXJyb3JgIGluc3RhbmNlIHJhdGhlclxuICAgIC8vIHRoYW4gdGhpcyBhbnRpLXBhdHRlcm4gb2YgdGhyb3dpbmcgc3RyaW5nc1xuICAgIHRocm93ICdPbmx5IHRoZSBhZnRlckxvZ291dCB0cmlnZ2VyIGlzIGFsbG93ZWQgZm9yIHRoZSBfU2Vzc2lvbiBjbGFzcy4nO1xuICB9XG4gIHJldHVybiBjbGFzc05hbWU7XG59XG5cbmNvbnN0IF90cmlnZ2VyU3RvcmUgPSB7fTtcblxuY29uc3QgQ2F0ZWdvcnkgPSB7XG4gIEZ1bmN0aW9uczogJ0Z1bmN0aW9ucycsXG4gIFZhbGlkYXRvcnM6ICdWYWxpZGF0b3JzJyxcbiAgSm9iczogJ0pvYnMnLFxuICBUcmlnZ2VyczogJ1RyaWdnZXJzJyxcbn07XG5cbmZ1bmN0aW9uIGdldFN0b3JlKGNhdGVnb3J5LCBuYW1lLCBhcHBsaWNhdGlvbklkKSB7XG4gIGNvbnN0IHBhdGggPSBuYW1lLnNwbGl0KCcuJyk7XG4gIHBhdGguc3BsaWNlKC0xKTsgLy8gcmVtb3ZlIGxhc3QgY29tcG9uZW50XG4gIGFwcGxpY2F0aW9uSWQgPSBhcHBsaWNhdGlvbklkIHx8IFBhcnNlLmFwcGxpY2F0aW9uSWQ7XG4gIF90cmlnZ2VyU3RvcmVbYXBwbGljYXRpb25JZF0gPSBfdHJpZ2dlclN0b3JlW2FwcGxpY2F0aW9uSWRdIHx8IGJhc2VTdG9yZSgpO1xuICBsZXQgc3RvcmUgPSBfdHJpZ2dlclN0b3JlW2FwcGxpY2F0aW9uSWRdW2NhdGVnb3J5XTtcbiAgZm9yIChjb25zdCBjb21wb25lbnQgb2YgcGF0aCkge1xuICAgIHN0b3JlID0gc3RvcmVbY29tcG9uZW50XTtcbiAgICBpZiAoIXN0b3JlKSB7XG4gICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgIH1cbiAgfVxuICByZXR1cm4gc3RvcmU7XG59XG5cbmZ1bmN0aW9uIGFkZChjYXRlZ29yeSwgbmFtZSwgaGFuZGxlciwgYXBwbGljYXRpb25JZCkge1xuICBjb25zdCBsYXN0Q29tcG9uZW50ID0gbmFtZS5zcGxpdCgnLicpLnNwbGljZSgtMSk7XG4gIGNvbnN0IHN0b3JlID0gZ2V0U3RvcmUoY2F0ZWdvcnksIG5hbWUsIGFwcGxpY2F0aW9uSWQpO1xuICBpZiAoc3RvcmVbbGFzdENvbXBvbmVudF0pIHtcbiAgICBsb2dnZXIud2FybihcbiAgICAgIGBXYXJuaW5nOiBEdXBsaWNhdGUgY2xvdWQgZnVuY3Rpb25zIGV4aXN0IGZvciAke2xhc3RDb21wb25lbnR9LiBPbmx5IHRoZSBsYXN0IG9uZSB3aWxsIGJlIHVzZWQgYW5kIHRoZSBvdGhlcnMgd2lsbCBiZSBpZ25vcmVkLmBcbiAgICApO1xuICB9XG4gIHN0b3JlW2xhc3RDb21wb25lbnRdID0gaGFuZGxlcjtcbn1cblxuZnVuY3Rpb24gcmVtb3ZlKGNhdGVnb3J5LCBuYW1lLCBhcHBsaWNhdGlvbklkKSB7XG4gIGNvbnN0IGxhc3RDb21wb25lbnQgPSBuYW1lLnNwbGl0KCcuJykuc3BsaWNlKC0xKTtcbiAgY29uc3Qgc3RvcmUgPSBnZXRTdG9yZShjYXRlZ29yeSwgbmFtZSwgYXBwbGljYXRpb25JZCk7XG4gIGRlbGV0ZSBzdG9yZVtsYXN0Q29tcG9uZW50XTtcbn1cblxuZnVuY3Rpb24gZ2V0KGNhdGVnb3J5LCBuYW1lLCBhcHBsaWNhdGlvbklkKSB7XG4gIGNvbnN0IGxhc3RDb21wb25lbnQgPSBuYW1lLnNwbGl0KCcuJykuc3BsaWNlKC0xKTtcbiAgY29uc3Qgc3RvcmUgPSBnZXRTdG9yZShjYXRlZ29yeSwgbmFtZSwgYXBwbGljYXRpb25JZCk7XG4gIHJldHVybiBzdG9yZVtsYXN0Q29tcG9uZW50XTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGFkZEZ1bmN0aW9uKGZ1bmN0aW9uTmFtZSwgaGFuZGxlciwgdmFsaWRhdGlvbkhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpIHtcbiAgYWRkKENhdGVnb3J5LkZ1bmN0aW9ucywgZnVuY3Rpb25OYW1lLCBoYW5kbGVyLCBhcHBsaWNhdGlvbklkKTtcbiAgYWRkKENhdGVnb3J5LlZhbGlkYXRvcnMsIGZ1bmN0aW9uTmFtZSwgdmFsaWRhdGlvbkhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gYWRkSm9iKGpvYk5hbWUsIGhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpIHtcbiAgYWRkKENhdGVnb3J5LkpvYnMsIGpvYk5hbWUsIGhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gYWRkVHJpZ2dlcih0eXBlLCBjbGFzc05hbWUsIGhhbmRsZXIsIGFwcGxpY2F0aW9uSWQsIHZhbGlkYXRpb25IYW5kbGVyKSB7XG4gIHZhbGlkYXRlQ2xhc3NOYW1lRm9yVHJpZ2dlcnMoY2xhc3NOYW1lLCB0eXBlKTtcbiAgYWRkKENhdGVnb3J5LlRyaWdnZXJzLCBgJHt0eXBlfS4ke2NsYXNzTmFtZX1gLCBoYW5kbGVyLCBhcHBsaWNhdGlvbklkKTtcbiAgYWRkKENhdGVnb3J5LlZhbGlkYXRvcnMsIGAke3R5cGV9LiR7Y2xhc3NOYW1lfWAsIHZhbGlkYXRpb25IYW5kbGVyLCBhcHBsaWNhdGlvbklkKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGFkZEZpbGVUcmlnZ2VyKHR5cGUsIGhhbmRsZXIsIGFwcGxpY2F0aW9uSWQsIHZhbGlkYXRpb25IYW5kbGVyKSB7XG4gIGFkZChDYXRlZ29yeS5UcmlnZ2VycywgYCR7dHlwZX0uJHtGaWxlQ2xhc3NOYW1lfWAsIGhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpO1xuICBhZGQoQ2F0ZWdvcnkuVmFsaWRhdG9ycywgYCR7dHlwZX0uJHtGaWxlQ2xhc3NOYW1lfWAsIHZhbGlkYXRpb25IYW5kbGVyLCBhcHBsaWNhdGlvbklkKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGFkZENvbm5lY3RUcmlnZ2VyKHR5cGUsIGhhbmRsZXIsIGFwcGxpY2F0aW9uSWQsIHZhbGlkYXRpb25IYW5kbGVyKSB7XG4gIGFkZChDYXRlZ29yeS5UcmlnZ2VycywgYCR7dHlwZX0uJHtDb25uZWN0Q2xhc3NOYW1lfWAsIGhhbmRsZXIsIGFwcGxpY2F0aW9uSWQpO1xuICBhZGQoQ2F0ZWdvcnkuVmFsaWRhdG9ycywgYCR7dHlwZX0uJHtDb25uZWN0Q2xhc3NOYW1lfWAsIHZhbGlkYXRpb25IYW5kbGVyLCBhcHBsaWNhdGlvbklkKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGFkZExpdmVRdWVyeUV2ZW50SGFuZGxlcihoYW5kbGVyLCBhcHBsaWNhdGlvbklkKSB7XG4gIGFwcGxpY2F0aW9uSWQgPSBhcHBsaWNhdGlvbklkIHx8IFBhcnNlLmFwcGxpY2F0aW9uSWQ7XG4gIF90cmlnZ2VyU3RvcmVbYXBwbGljYXRpb25JZF0gPSBfdHJpZ2dlclN0b3JlW2FwcGxpY2F0aW9uSWRdIHx8IGJhc2VTdG9yZSgpO1xuICBfdHJpZ2dlclN0b3JlW2FwcGxpY2F0aW9uSWRdLkxpdmVRdWVyeS5wdXNoKGhhbmRsZXIpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gcmVtb3ZlRnVuY3Rpb24oZnVuY3Rpb25OYW1lLCBhcHBsaWNhdGlvbklkKSB7XG4gIHJlbW92ZShDYXRlZ29yeS5GdW5jdGlvbnMsIGZ1bmN0aW9uTmFtZSwgYXBwbGljYXRpb25JZCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZW1vdmVUcmlnZ2VyKHR5cGUsIGNsYXNzTmFtZSwgYXBwbGljYXRpb25JZCkge1xuICByZW1vdmUoQ2F0ZWdvcnkuVHJpZ2dlcnMsIGAke3R5cGV9LiR7Y2xhc3NOYW1lfWAsIGFwcGxpY2F0aW9uSWQpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gX3VucmVnaXN0ZXJBbGwoKSB7XG4gIE9iamVjdC5rZXlzKF90cmlnZ2VyU3RvcmUpLmZvckVhY2goYXBwSWQgPT4gZGVsZXRlIF90cmlnZ2VyU3RvcmVbYXBwSWRdKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGdldFRyaWdnZXIoY2xhc3NOYW1lLCB0cmlnZ2VyVHlwZSwgYXBwbGljYXRpb25JZCkge1xuICBpZiAoIWFwcGxpY2F0aW9uSWQpIHtcbiAgICB0aHJvdyAnTWlzc2luZyBBcHBsaWNhdGlvbklEJztcbiAgfVxuICByZXR1cm4gZ2V0KENhdGVnb3J5LlRyaWdnZXJzLCBgJHt0cmlnZ2VyVHlwZX0uJHtjbGFzc05hbWV9YCwgYXBwbGljYXRpb25JZCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRGaWxlVHJpZ2dlcih0eXBlLCBhcHBsaWNhdGlvbklkKSB7XG4gIHJldHVybiBnZXRUcmlnZ2VyKEZpbGVDbGFzc05hbWUsIHR5cGUsIGFwcGxpY2F0aW9uSWQpO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gdHJpZ2dlckV4aXN0cyhjbGFzc05hbWU6IHN0cmluZywgdHlwZTogc3RyaW5nLCBhcHBsaWNhdGlvbklkOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgcmV0dXJuIGdldFRyaWdnZXIoY2xhc3NOYW1lLCB0eXBlLCBhcHBsaWNhdGlvbklkKSAhPSB1bmRlZmluZWQ7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRGdW5jdGlvbihmdW5jdGlvbk5hbWUsIGFwcGxpY2F0aW9uSWQpIHtcbiAgcmV0dXJuIGdldChDYXRlZ29yeS5GdW5jdGlvbnMsIGZ1bmN0aW9uTmFtZSwgYXBwbGljYXRpb25JZCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRGdW5jdGlvbk5hbWVzKGFwcGxpY2F0aW9uSWQpIHtcbiAgY29uc3Qgc3RvcmUgPVxuICAgIChfdHJpZ2dlclN0b3JlW2FwcGxpY2F0aW9uSWRdICYmIF90cmlnZ2VyU3RvcmVbYXBwbGljYXRpb25JZF1bQ2F0ZWdvcnkuRnVuY3Rpb25zXSkgfHwge307XG4gIGNvbnN0IGZ1bmN0aW9uTmFtZXMgPSBbXTtcbiAgY29uc3QgZXh0cmFjdEZ1bmN0aW9uTmFtZXMgPSAobmFtZXNwYWNlLCBzdG9yZSkgPT4ge1xuICAgIE9iamVjdC5rZXlzKHN0b3JlKS5mb3JFYWNoKG5hbWUgPT4ge1xuICAgICAgY29uc3QgdmFsdWUgPSBzdG9yZVtuYW1lXTtcbiAgICAgIGlmIChuYW1lc3BhY2UpIHtcbiAgICAgICAgbmFtZSA9IGAke25hbWVzcGFjZX0uJHtuYW1lfWA7XG4gICAgICB9XG4gICAgICBpZiAodHlwZW9mIHZhbHVlID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgIGZ1bmN0aW9uTmFtZXMucHVzaChuYW1lKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGV4dHJhY3RGdW5jdGlvbk5hbWVzKG5hbWUsIHZhbHVlKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfTtcbiAgZXh0cmFjdEZ1bmN0aW9uTmFtZXMobnVsbCwgc3RvcmUpO1xuICByZXR1cm4gZnVuY3Rpb25OYW1lcztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGdldEpvYihqb2JOYW1lLCBhcHBsaWNhdGlvbklkKSB7XG4gIHJldHVybiBnZXQoQ2F0ZWdvcnkuSm9icywgam9iTmFtZSwgYXBwbGljYXRpb25JZCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRKb2JzKGFwcGxpY2F0aW9uSWQpIHtcbiAgdmFyIG1hbmFnZXIgPSBfdHJpZ2dlclN0b3JlW2FwcGxpY2F0aW9uSWRdO1xuICBpZiAobWFuYWdlciAmJiBtYW5hZ2VyLkpvYnMpIHtcbiAgICByZXR1cm4gbWFuYWdlci5Kb2JzO1xuICB9XG4gIHJldHVybiB1bmRlZmluZWQ7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRWYWxpZGF0b3IoZnVuY3Rpb25OYW1lLCBhcHBsaWNhdGlvbklkKSB7XG4gIHJldHVybiBnZXQoQ2F0ZWdvcnkuVmFsaWRhdG9ycywgZnVuY3Rpb25OYW1lLCBhcHBsaWNhdGlvbklkKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGdldFJlcXVlc3RPYmplY3QoXG4gIHRyaWdnZXJUeXBlLFxuICBhdXRoLFxuICBwYXJzZU9iamVjdCxcbiAgb3JpZ2luYWxQYXJzZU9iamVjdCxcbiAgY29uZmlnLFxuICBjb250ZXh0XG4pIHtcbiAgY29uc3QgcmVxdWVzdCA9IHtcbiAgICB0cmlnZ2VyTmFtZTogdHJpZ2dlclR5cGUsXG4gICAgb2JqZWN0OiBwYXJzZU9iamVjdCxcbiAgICBtYXN0ZXI6IGZhbHNlLFxuICAgIGxvZzogY29uZmlnLmxvZ2dlckNvbnRyb2xsZXIsXG4gICAgaGVhZGVyczogY29uZmlnLmhlYWRlcnMsXG4gICAgaXA6IGNvbmZpZy5pcCxcbiAgfTtcblxuICBpZiAob3JpZ2luYWxQYXJzZU9iamVjdCkge1xuICAgIHJlcXVlc3Qub3JpZ2luYWwgPSBvcmlnaW5hbFBhcnNlT2JqZWN0O1xuICB9XG4gIGlmIChcbiAgICB0cmlnZ2VyVHlwZSA9PT0gVHlwZXMuYmVmb3JlU2F2ZSB8fFxuICAgIHRyaWdnZXJUeXBlID09PSBUeXBlcy5hZnRlclNhdmUgfHxcbiAgICB0cmlnZ2VyVHlwZSA9PT0gVHlwZXMuYmVmb3JlRGVsZXRlIHx8XG4gICAgdHJpZ2dlclR5cGUgPT09IFR5cGVzLmFmdGVyRGVsZXRlIHx8XG4gICAgdHJpZ2dlclR5cGUgPT09IFR5cGVzLmFmdGVyRmluZFxuICApIHtcbiAgICAvLyBTZXQgYSBjb3B5IG9mIHRoZSBjb250ZXh0IG9uIHRoZSByZXF1ZXN0IG9iamVjdC5cbiAgICByZXF1ZXN0LmNvbnRleHQgPSBPYmplY3QuYXNzaWduKHt9LCBjb250ZXh0KTtcbiAgfVxuXG4gIGlmICghYXV0aCkge1xuICAgIHJldHVybiByZXF1ZXN0O1xuICB9XG4gIGlmIChhdXRoLmlzTWFzdGVyKSB7XG4gICAgcmVxdWVzdFsnbWFzdGVyJ10gPSB0cnVlO1xuICB9XG4gIGlmIChhdXRoLnVzZXIpIHtcbiAgICByZXF1ZXN0Wyd1c2VyJ10gPSBhdXRoLnVzZXI7XG4gIH1cbiAgaWYgKGF1dGguaW5zdGFsbGF0aW9uSWQpIHtcbiAgICByZXF1ZXN0WydpbnN0YWxsYXRpb25JZCddID0gYXV0aC5pbnN0YWxsYXRpb25JZDtcbiAgfVxuICByZXR1cm4gcmVxdWVzdDtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGdldFJlcXVlc3RRdWVyeU9iamVjdCh0cmlnZ2VyVHlwZSwgYXV0aCwgcXVlcnksIGNvdW50LCBjb25maWcsIGNvbnRleHQsIGlzR2V0KSB7XG4gIGlzR2V0ID0gISFpc0dldDtcblxuICB2YXIgcmVxdWVzdCA9IHtcbiAgICB0cmlnZ2VyTmFtZTogdHJpZ2dlclR5cGUsXG4gICAgcXVlcnksXG4gICAgbWFzdGVyOiBmYWxzZSxcbiAgICBjb3VudCxcbiAgICBsb2c6IGNvbmZpZy5sb2dnZXJDb250cm9sbGVyLFxuICAgIGlzR2V0LFxuICAgIGhlYWRlcnM6IGNvbmZpZy5oZWFkZXJzLFxuICAgIGlwOiBjb25maWcuaXAsXG4gICAgY29udGV4dDogY29udGV4dCB8fCB7fSxcbiAgfTtcblxuICBpZiAoIWF1dGgpIHtcbiAgICByZXR1cm4gcmVxdWVzdDtcbiAgfVxuICBpZiAoYXV0aC5pc01hc3Rlcikge1xuICAgIHJlcXVlc3RbJ21hc3RlciddID0gdHJ1ZTtcbiAgfVxuICBpZiAoYXV0aC51c2VyKSB7XG4gICAgcmVxdWVzdFsndXNlciddID0gYXV0aC51c2VyO1xuICB9XG4gIGlmIChhdXRoLmluc3RhbGxhdGlvbklkKSB7XG4gICAgcmVxdWVzdFsnaW5zdGFsbGF0aW9uSWQnXSA9IGF1dGguaW5zdGFsbGF0aW9uSWQ7XG4gIH1cbiAgcmV0dXJuIHJlcXVlc3Q7XG59XG5cbi8vIENyZWF0ZXMgdGhlIHJlc3BvbnNlIG9iamVjdCwgYW5kIHVzZXMgdGhlIHJlcXVlc3Qgb2JqZWN0IHRvIHBhc3MgZGF0YVxuLy8gVGhlIEFQSSB3aWxsIGNhbGwgdGhpcyB3aXRoIFJFU1QgQVBJIGZvcm1hdHRlZCBvYmplY3RzLCB0aGlzIHdpbGxcbi8vIHRyYW5zZm9ybSB0aGVtIHRvIFBhcnNlLk9iamVjdCBpbnN0YW5jZXMgZXhwZWN0ZWQgYnkgQ2xvdWQgQ29kZS5cbi8vIEFueSBjaGFuZ2VzIG1hZGUgdG8gdGhlIG9iamVjdCBpbiBhIGJlZm9yZVNhdmUgd2lsbCBiZSBpbmNsdWRlZC5cbmV4cG9ydCBmdW5jdGlvbiBnZXRSZXNwb25zZU9iamVjdChyZXF1ZXN0LCByZXNvbHZlLCByZWplY3QpIHtcbiAgcmV0dXJuIHtcbiAgICBzdWNjZXNzOiBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgIGlmIChyZXF1ZXN0LnRyaWdnZXJOYW1lID09PSBUeXBlcy5hZnRlckZpbmQpIHtcbiAgICAgICAgaWYgKCFyZXNwb25zZSkge1xuICAgICAgICAgIHJlc3BvbnNlID0gcmVxdWVzdC5vYmplY3RzO1xuICAgICAgICB9XG4gICAgICAgIHJlc3BvbnNlID0gcmVzcG9uc2UubWFwKG9iamVjdCA9PiB7XG4gICAgICAgICAgcmV0dXJuIG9iamVjdC50b0pTT04oKTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiByZXNvbHZlKHJlc3BvbnNlKTtcbiAgICAgIH1cbiAgICAgIC8vIFVzZSB0aGUgSlNPTiByZXNwb25zZVxuICAgICAgaWYgKFxuICAgICAgICByZXNwb25zZSAmJlxuICAgICAgICB0eXBlb2YgcmVzcG9uc2UgPT09ICdvYmplY3QnICYmXG4gICAgICAgICFyZXF1ZXN0Lm9iamVjdC5lcXVhbHMocmVzcG9uc2UpICYmXG4gICAgICAgIHJlcXVlc3QudHJpZ2dlck5hbWUgPT09IFR5cGVzLmJlZm9yZVNhdmVcbiAgICAgICkge1xuICAgICAgICByZXR1cm4gcmVzb2x2ZShyZXNwb25zZSk7XG4gICAgICB9XG4gICAgICBpZiAocmVzcG9uc2UgJiYgdHlwZW9mIHJlc3BvbnNlID09PSAnb2JqZWN0JyAmJiByZXF1ZXN0LnRyaWdnZXJOYW1lID09PSBUeXBlcy5hZnRlclNhdmUpIHtcbiAgICAgICAgcmV0dXJuIHJlc29sdmUocmVzcG9uc2UpO1xuICAgICAgfVxuICAgICAgaWYgKHJlcXVlc3QudHJpZ2dlck5hbWUgPT09IFR5cGVzLmFmdGVyU2F2ZSkge1xuICAgICAgICByZXR1cm4gcmVzb2x2ZSgpO1xuICAgICAgfVxuICAgICAgcmVzcG9uc2UgPSB7fTtcbiAgICAgIGlmIChyZXF1ZXN0LnRyaWdnZXJOYW1lID09PSBUeXBlcy5iZWZvcmVTYXZlKSB7XG4gICAgICAgIHJlc3BvbnNlWydvYmplY3QnXSA9IHJlcXVlc3Qub2JqZWN0Ll9nZXRTYXZlSlNPTigpO1xuICAgICAgICByZXNwb25zZVsnb2JqZWN0J11bJ29iamVjdElkJ10gPSByZXF1ZXN0Lm9iamVjdC5pZDtcbiAgICAgIH1cbiAgICAgIHJldHVybiByZXNvbHZlKHJlc3BvbnNlKTtcbiAgICB9LFxuICAgIGVycm9yOiBmdW5jdGlvbiAoZXJyb3IpIHtcbiAgICAgIGNvbnN0IGUgPSByZXNvbHZlRXJyb3IoZXJyb3IsIHtcbiAgICAgICAgY29kZTogUGFyc2UuRXJyb3IuU0NSSVBUX0ZBSUxFRCxcbiAgICAgICAgbWVzc2FnZTogJ1NjcmlwdCBmYWlsZWQuIFVua25vd24gZXJyb3IuJyxcbiAgICAgIH0pO1xuICAgICAgcmVqZWN0KGUpO1xuICAgIH0sXG4gIH07XG59XG5cbmZ1bmN0aW9uIHVzZXJJZEZvckxvZyhhdXRoKSB7XG4gIHJldHVybiBhdXRoICYmIGF1dGgudXNlciA/IGF1dGgudXNlci5pZCA6IHVuZGVmaW5lZDtcbn1cblxuZnVuY3Rpb24gbG9nVHJpZ2dlckFmdGVySG9vayh0cmlnZ2VyVHlwZSwgY2xhc3NOYW1lLCBpbnB1dCwgYXV0aCkge1xuICBjb25zdCBjbGVhbklucHV0ID0gbG9nZ2VyLnRydW5jYXRlTG9nTWVzc2FnZShKU09OLnN0cmluZ2lmeShpbnB1dCkpO1xuICBsb2dnZXIuaW5mbyhcbiAgICBgJHt0cmlnZ2VyVHlwZX0gdHJpZ2dlcmVkIGZvciAke2NsYXNzTmFtZX0gZm9yIHVzZXIgJHt1c2VySWRGb3JMb2coXG4gICAgICBhdXRoXG4gICAgKX06XFxuICBJbnB1dDogJHtjbGVhbklucHV0fWAsXG4gICAge1xuICAgICAgY2xhc3NOYW1lLFxuICAgICAgdHJpZ2dlclR5cGUsXG4gICAgICB1c2VyOiB1c2VySWRGb3JMb2coYXV0aCksXG4gICAgfVxuICApO1xufVxuXG5mdW5jdGlvbiBsb2dUcmlnZ2VyU3VjY2Vzc0JlZm9yZUhvb2sodHJpZ2dlclR5cGUsIGNsYXNzTmFtZSwgaW5wdXQsIHJlc3VsdCwgYXV0aCkge1xuICBjb25zdCBjbGVhbklucHV0ID0gbG9nZ2VyLnRydW5jYXRlTG9nTWVzc2FnZShKU09OLnN0cmluZ2lmeShpbnB1dCkpO1xuICBjb25zdCBjbGVhblJlc3VsdCA9IGxvZ2dlci50cnVuY2F0ZUxvZ01lc3NhZ2UoSlNPTi5zdHJpbmdpZnkocmVzdWx0KSk7XG4gIGxvZ2dlci5pbmZvKFxuICAgIGAke3RyaWdnZXJUeXBlfSB0cmlnZ2VyZWQgZm9yICR7Y2xhc3NOYW1lfSBmb3IgdXNlciAke3VzZXJJZEZvckxvZyhcbiAgICAgIGF1dGhcbiAgICApfTpcXG4gIElucHV0OiAke2NsZWFuSW5wdXR9XFxuICBSZXN1bHQ6ICR7Y2xlYW5SZXN1bHR9YCxcbiAgICB7XG4gICAgICBjbGFzc05hbWUsXG4gICAgICB0cmlnZ2VyVHlwZSxcbiAgICAgIHVzZXI6IHVzZXJJZEZvckxvZyhhdXRoKSxcbiAgICB9XG4gICk7XG59XG5cbmZ1bmN0aW9uIGxvZ1RyaWdnZXJFcnJvckJlZm9yZUhvb2sodHJpZ2dlclR5cGUsIGNsYXNzTmFtZSwgaW5wdXQsIGF1dGgsIGVycm9yKSB7XG4gIGNvbnN0IGNsZWFuSW5wdXQgPSBsb2dnZXIudHJ1bmNhdGVMb2dNZXNzYWdlKEpTT04uc3RyaW5naWZ5KGlucHV0KSk7XG4gIGxvZ2dlci5lcnJvcihcbiAgICBgJHt0cmlnZ2VyVHlwZX0gZmFpbGVkIGZvciAke2NsYXNzTmFtZX0gZm9yIHVzZXIgJHt1c2VySWRGb3JMb2coXG4gICAgICBhdXRoXG4gICAgKX06XFxuICBJbnB1dDogJHtjbGVhbklucHV0fVxcbiAgRXJyb3I6ICR7SlNPTi5zdHJpbmdpZnkoZXJyb3IpfWAsXG4gICAge1xuICAgICAgY2xhc3NOYW1lLFxuICAgICAgdHJpZ2dlclR5cGUsXG4gICAgICBlcnJvcixcbiAgICAgIHVzZXI6IHVzZXJJZEZvckxvZyhhdXRoKSxcbiAgICB9XG4gICk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBtYXliZVJ1bkFmdGVyRmluZFRyaWdnZXIoXG4gIHRyaWdnZXJUeXBlLFxuICBhdXRoLFxuICBjbGFzc05hbWUsXG4gIG9iamVjdHMsXG4gIGNvbmZpZyxcbiAgcXVlcnksXG4gIGNvbnRleHRcbikge1xuICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xuICAgIGNvbnN0IHRyaWdnZXIgPSBnZXRUcmlnZ2VyKGNsYXNzTmFtZSwgdHJpZ2dlclR5cGUsIGNvbmZpZy5hcHBsaWNhdGlvbklkKTtcbiAgICBpZiAoIXRyaWdnZXIpIHtcbiAgICAgIHJldHVybiByZXNvbHZlKCk7XG4gICAgfVxuICAgIGNvbnN0IHJlcXVlc3QgPSBnZXRSZXF1ZXN0T2JqZWN0KHRyaWdnZXJUeXBlLCBhdXRoLCBudWxsLCBudWxsLCBjb25maWcsIGNvbnRleHQpO1xuICAgIGlmIChxdWVyeSkge1xuICAgICAgcmVxdWVzdC5xdWVyeSA9IHF1ZXJ5O1xuICAgIH1cbiAgICBjb25zdCB7IHN1Y2Nlc3MsIGVycm9yIH0gPSBnZXRSZXNwb25zZU9iamVjdChcbiAgICAgIHJlcXVlc3QsXG4gICAgICBvYmplY3QgPT4ge1xuICAgICAgICByZXNvbHZlKG9iamVjdCk7XG4gICAgICB9LFxuICAgICAgZXJyb3IgPT4ge1xuICAgICAgICByZWplY3QoZXJyb3IpO1xuICAgICAgfVxuICAgICk7XG4gICAgbG9nVHJpZ2dlclN1Y2Nlc3NCZWZvcmVIb29rKHRyaWdnZXJUeXBlLCBjbGFzc05hbWUsICdBZnRlckZpbmQnLCBKU09OLnN0cmluZ2lmeShvYmplY3RzKSwgYXV0aCk7XG4gICAgcmVxdWVzdC5vYmplY3RzID0gb2JqZWN0cy5tYXAob2JqZWN0ID0+IHtcbiAgICAgIC8vc2V0dGluZyB0aGUgY2xhc3MgbmFtZSB0byB0cmFuc2Zvcm0gaW50byBwYXJzZSBvYmplY3RcbiAgICAgIG9iamVjdC5jbGFzc05hbWUgPSBjbGFzc05hbWU7XG4gICAgICByZXR1cm4gUGFyc2UuT2JqZWN0LmZyb21KU09OKG9iamVjdCk7XG4gICAgfSk7XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpXG4gICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgIHJldHVybiBtYXliZVJ1blZhbGlkYXRvcihyZXF1ZXN0LCBgJHt0cmlnZ2VyVHlwZX0uJHtjbGFzc05hbWV9YCk7XG4gICAgICB9KVxuICAgICAgLnRoZW4oKCkgPT4ge1xuICAgICAgICBpZiAocmVxdWVzdC5za2lwV2l0aE1hc3RlcktleSkge1xuICAgICAgICAgIHJldHVybiByZXF1ZXN0Lm9iamVjdHM7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgcmVzcG9uc2UgPSB0cmlnZ2VyKHJlcXVlc3QpO1xuICAgICAgICBpZiAocmVzcG9uc2UgJiYgdHlwZW9mIHJlc3BvbnNlLnRoZW4gPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgICByZXR1cm4gcmVzcG9uc2UudGhlbihyZXN1bHRzID0+IHtcbiAgICAgICAgICAgIGlmICghcmVzdWx0cykge1xuICAgICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICAgICAgUGFyc2UuRXJyb3IuU0NSSVBUX0ZBSUxFRCxcbiAgICAgICAgICAgICAgICAnQWZ0ZXJGaW5kIGV4cGVjdCByZXN1bHRzIHRvIGJlIHJldHVybmVkIGluIHRoZSBwcm9taXNlJ1xuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHJlc3VsdHM7XG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHJlc3BvbnNlO1xuICAgICAgfSlcbiAgICAgIC50aGVuKHN1Y2Nlc3MsIGVycm9yKTtcbiAgfSkudGhlbihyZXN1bHRzID0+IHtcbiAgICBsb2dUcmlnZ2VyQWZ0ZXJIb29rKHRyaWdnZXJUeXBlLCBjbGFzc05hbWUsIEpTT04uc3RyaW5naWZ5KHJlc3VsdHMpLCBhdXRoKTtcbiAgICByZXR1cm4gcmVzdWx0cztcbiAgfSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBtYXliZVJ1blF1ZXJ5VHJpZ2dlcihcbiAgdHJpZ2dlclR5cGUsXG4gIGNsYXNzTmFtZSxcbiAgcmVzdFdoZXJlLFxuICByZXN0T3B0aW9ucyxcbiAgY29uZmlnLFxuICBhdXRoLFxuICBjb250ZXh0LFxuICBpc0dldFxuKSB7XG4gIGNvbnN0IHRyaWdnZXIgPSBnZXRUcmlnZ2VyKGNsYXNzTmFtZSwgdHJpZ2dlclR5cGUsIGNvbmZpZy5hcHBsaWNhdGlvbklkKTtcbiAgaWYgKCF0cmlnZ2VyKSB7XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh7XG4gICAgICByZXN0V2hlcmUsXG4gICAgICByZXN0T3B0aW9ucyxcbiAgICB9KTtcbiAgfVxuICBjb25zdCBqc29uID0gT2JqZWN0LmFzc2lnbih7fSwgcmVzdE9wdGlvbnMpO1xuICBqc29uLndoZXJlID0gcmVzdFdoZXJlO1xuXG4gIGNvbnN0IHBhcnNlUXVlcnkgPSBuZXcgUGFyc2UuUXVlcnkoY2xhc3NOYW1lKTtcbiAgcGFyc2VRdWVyeS53aXRoSlNPTihqc29uKTtcblxuICBsZXQgY291bnQgPSBmYWxzZTtcbiAgaWYgKHJlc3RPcHRpb25zKSB7XG4gICAgY291bnQgPSAhIXJlc3RPcHRpb25zLmNvdW50O1xuICB9XG4gIGNvbnN0IHJlcXVlc3RPYmplY3QgPSBnZXRSZXF1ZXN0UXVlcnlPYmplY3QoXG4gICAgdHJpZ2dlclR5cGUsXG4gICAgYXV0aCxcbiAgICBwYXJzZVF1ZXJ5LFxuICAgIGNvdW50LFxuICAgIGNvbmZpZyxcbiAgICBjb250ZXh0LFxuICAgIGlzR2V0XG4gICk7XG4gIHJldHVybiBQcm9taXNlLnJlc29sdmUoKVxuICAgIC50aGVuKCgpID0+IHtcbiAgICAgIHJldHVybiBtYXliZVJ1blZhbGlkYXRvcihyZXF1ZXN0T2JqZWN0LCBgJHt0cmlnZ2VyVHlwZX0uJHtjbGFzc05hbWV9YCk7XG4gICAgfSlcbiAgICAudGhlbigoKSA9PiB7XG4gICAgICBpZiAocmVxdWVzdE9iamVjdC5za2lwV2l0aE1hc3RlcktleSkge1xuICAgICAgICByZXR1cm4gcmVxdWVzdE9iamVjdC5xdWVyeTtcbiAgICAgIH1cbiAgICAgIHJldHVybiB0cmlnZ2VyKHJlcXVlc3RPYmplY3QpO1xuICAgIH0pXG4gICAgLnRoZW4oXG4gICAgICByZXN1bHQgPT4ge1xuICAgICAgICBsZXQgcXVlcnlSZXN1bHQgPSBwYXJzZVF1ZXJ5O1xuICAgICAgICBpZiAocmVzdWx0ICYmIHJlc3VsdCBpbnN0YW5jZW9mIFBhcnNlLlF1ZXJ5KSB7XG4gICAgICAgICAgcXVlcnlSZXN1bHQgPSByZXN1bHQ7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QganNvblF1ZXJ5ID0gcXVlcnlSZXN1bHQudG9KU09OKCk7XG4gICAgICAgIGlmIChqc29uUXVlcnkud2hlcmUpIHtcbiAgICAgICAgICByZXN0V2hlcmUgPSBqc29uUXVlcnkud2hlcmU7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGpzb25RdWVyeS5saW1pdCkge1xuICAgICAgICAgIHJlc3RPcHRpb25zID0gcmVzdE9wdGlvbnMgfHwge307XG4gICAgICAgICAgcmVzdE9wdGlvbnMubGltaXQgPSBqc29uUXVlcnkubGltaXQ7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGpzb25RdWVyeS5za2lwKSB7XG4gICAgICAgICAgcmVzdE9wdGlvbnMgPSByZXN0T3B0aW9ucyB8fCB7fTtcbiAgICAgICAgICByZXN0T3B0aW9ucy5za2lwID0ganNvblF1ZXJ5LnNraXA7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGpzb25RdWVyeS5pbmNsdWRlKSB7XG4gICAgICAgICAgcmVzdE9wdGlvbnMgPSByZXN0T3B0aW9ucyB8fCB7fTtcbiAgICAgICAgICByZXN0T3B0aW9ucy5pbmNsdWRlID0ganNvblF1ZXJ5LmluY2x1ZGU7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGpzb25RdWVyeS5leGNsdWRlS2V5cykge1xuICAgICAgICAgIHJlc3RPcHRpb25zID0gcmVzdE9wdGlvbnMgfHwge307XG4gICAgICAgICAgcmVzdE9wdGlvbnMuZXhjbHVkZUtleXMgPSBqc29uUXVlcnkuZXhjbHVkZUtleXM7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGpzb25RdWVyeS5leHBsYWluKSB7XG4gICAgICAgICAgcmVzdE9wdGlvbnMgPSByZXN0T3B0aW9ucyB8fCB7fTtcbiAgICAgICAgICByZXN0T3B0aW9ucy5leHBsYWluID0ganNvblF1ZXJ5LmV4cGxhaW47XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGpzb25RdWVyeS5rZXlzKSB7XG4gICAgICAgICAgcmVzdE9wdGlvbnMgPSByZXN0T3B0aW9ucyB8fCB7fTtcbiAgICAgICAgICByZXN0T3B0aW9ucy5rZXlzID0ganNvblF1ZXJ5LmtleXM7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGpzb25RdWVyeS5vcmRlcikge1xuICAgICAgICAgIHJlc3RPcHRpb25zID0gcmVzdE9wdGlvbnMgfHwge307XG4gICAgICAgICAgcmVzdE9wdGlvbnMub3JkZXIgPSBqc29uUXVlcnkub3JkZXI7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGpzb25RdWVyeS5oaW50KSB7XG4gICAgICAgICAgcmVzdE9wdGlvbnMgPSByZXN0T3B0aW9ucyB8fCB7fTtcbiAgICAgICAgICByZXN0T3B0aW9ucy5oaW50ID0ganNvblF1ZXJ5LmhpbnQ7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHJlcXVlc3RPYmplY3QucmVhZFByZWZlcmVuY2UpIHtcbiAgICAgICAgICByZXN0T3B0aW9ucyA9IHJlc3RPcHRpb25zIHx8IHt9O1xuICAgICAgICAgIHJlc3RPcHRpb25zLnJlYWRQcmVmZXJlbmNlID0gcmVxdWVzdE9iamVjdC5yZWFkUHJlZmVyZW5jZTtcbiAgICAgICAgfVxuICAgICAgICBpZiAocmVxdWVzdE9iamVjdC5pbmNsdWRlUmVhZFByZWZlcmVuY2UpIHtcbiAgICAgICAgICByZXN0T3B0aW9ucyA9IHJlc3RPcHRpb25zIHx8IHt9O1xuICAgICAgICAgIHJlc3RPcHRpb25zLmluY2x1ZGVSZWFkUHJlZmVyZW5jZSA9IHJlcXVlc3RPYmplY3QuaW5jbHVkZVJlYWRQcmVmZXJlbmNlO1xuICAgICAgICB9XG4gICAgICAgIGlmIChyZXF1ZXN0T2JqZWN0LnN1YnF1ZXJ5UmVhZFByZWZlcmVuY2UpIHtcbiAgICAgICAgICByZXN0T3B0aW9ucyA9IHJlc3RPcHRpb25zIHx8IHt9O1xuICAgICAgICAgIHJlc3RPcHRpb25zLnN1YnF1ZXJ5UmVhZFByZWZlcmVuY2UgPSByZXF1ZXN0T2JqZWN0LnN1YnF1ZXJ5UmVhZFByZWZlcmVuY2U7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICByZXN0V2hlcmUsXG4gICAgICAgICAgcmVzdE9wdGlvbnMsXG4gICAgICAgIH07XG4gICAgICB9LFxuICAgICAgZXJyID0+IHtcbiAgICAgICAgY29uc3QgZXJyb3IgPSByZXNvbHZlRXJyb3IoZXJyLCB7XG4gICAgICAgICAgY29kZTogUGFyc2UuRXJyb3IuU0NSSVBUX0ZBSUxFRCxcbiAgICAgICAgICBtZXNzYWdlOiAnU2NyaXB0IGZhaWxlZC4gVW5rbm93biBlcnJvci4nLFxuICAgICAgICB9KTtcbiAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICB9XG4gICAgKTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHJlc29sdmVFcnJvcihtZXNzYWdlLCBkZWZhdWx0T3B0cykge1xuICBpZiAoIWRlZmF1bHRPcHRzKSB7XG4gICAgZGVmYXVsdE9wdHMgPSB7fTtcbiAgfVxuICBpZiAoIW1lc3NhZ2UpIHtcbiAgICByZXR1cm4gbmV3IFBhcnNlLkVycm9yKFxuICAgICAgZGVmYXVsdE9wdHMuY29kZSB8fCBQYXJzZS5FcnJvci5TQ1JJUFRfRkFJTEVELFxuICAgICAgZGVmYXVsdE9wdHMubWVzc2FnZSB8fCAnU2NyaXB0IGZhaWxlZC4nXG4gICAgKTtcbiAgfVxuICBpZiAobWVzc2FnZSBpbnN0YW5jZW9mIFBhcnNlLkVycm9yKSB7XG4gICAgcmV0dXJuIG1lc3NhZ2U7XG4gIH1cblxuICBjb25zdCBjb2RlID0gZGVmYXVsdE9wdHMuY29kZSB8fCBQYXJzZS5FcnJvci5TQ1JJUFRfRkFJTEVEO1xuICAvLyBJZiBpdCdzIGFuIGVycm9yLCBtYXJrIGl0IGFzIGEgc2NyaXB0IGZhaWxlZFxuICBpZiAodHlwZW9mIG1lc3NhZ2UgPT09ICdzdHJpbmcnKSB7XG4gICAgcmV0dXJuIG5ldyBQYXJzZS5FcnJvcihjb2RlLCBtZXNzYWdlKTtcbiAgfVxuICBjb25zdCBlcnJvciA9IG5ldyBQYXJzZS5FcnJvcihjb2RlLCBtZXNzYWdlLm1lc3NhZ2UgfHwgbWVzc2FnZSk7XG4gIGlmIChtZXNzYWdlIGluc3RhbmNlb2YgRXJyb3IpIHtcbiAgICBlcnJvci5zdGFjayA9IG1lc3NhZ2Uuc3RhY2s7XG4gIH1cbiAgcmV0dXJuIGVycm9yO1xufVxuZXhwb3J0IGZ1bmN0aW9uIG1heWJlUnVuVmFsaWRhdG9yKHJlcXVlc3QsIGZ1bmN0aW9uTmFtZSkge1xuICBjb25zdCB0aGVWYWxpZGF0b3IgPSBnZXRWYWxpZGF0b3IoZnVuY3Rpb25OYW1lLCBQYXJzZS5hcHBsaWNhdGlvbklkKTtcbiAgaWYgKCF0aGVWYWxpZGF0b3IpIHtcbiAgICByZXR1cm47XG4gIH1cbiAgaWYgKHR5cGVvZiB0aGVWYWxpZGF0b3IgPT09ICdvYmplY3QnICYmIHRoZVZhbGlkYXRvci5za2lwV2l0aE1hc3RlcktleSAmJiByZXF1ZXN0Lm1hc3Rlcikge1xuICAgIHJlcXVlc3Quc2tpcFdpdGhNYXN0ZXJLZXkgPSB0cnVlO1xuICB9XG4gIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpXG4gICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgIHJldHVybiB0eXBlb2YgdGhlVmFsaWRhdG9yID09PSAnb2JqZWN0J1xuICAgICAgICAgID8gYnVpbHRJblRyaWdnZXJWYWxpZGF0b3IodGhlVmFsaWRhdG9yLCByZXF1ZXN0KVxuICAgICAgICAgIDogdGhlVmFsaWRhdG9yKHJlcXVlc3QpO1xuICAgICAgfSlcbiAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgcmVzb2x2ZSgpO1xuICAgICAgfSlcbiAgICAgIC5jYXRjaChlID0+IHtcbiAgICAgICAgY29uc3QgZXJyb3IgPSByZXNvbHZlRXJyb3IoZSwge1xuICAgICAgICAgIGNvZGU6IFBhcnNlLkVycm9yLlZBTElEQVRJT05fRVJST1IsXG4gICAgICAgICAgbWVzc2FnZTogJ1ZhbGlkYXRpb24gZmFpbGVkLicsXG4gICAgICAgIH0pO1xuICAgICAgICByZWplY3QoZXJyb3IpO1xuICAgICAgfSk7XG4gIH0pO1xufVxuZnVuY3Rpb24gYnVpbHRJblRyaWdnZXJWYWxpZGF0b3Iob3B0aW9ucywgcmVxdWVzdCkge1xuICBpZiAocmVxdWVzdC5tYXN0ZXIgJiYgIW9wdGlvbnMudmFsaWRhdGVNYXN0ZXJLZXkpIHtcbiAgICByZXR1cm47XG4gIH1cbiAgbGV0IHJlcVVzZXIgPSByZXF1ZXN0LnVzZXI7XG4gIGlmIChcbiAgICAhcmVxVXNlciAmJlxuICAgIHJlcXVlc3Qub2JqZWN0ICYmXG4gICAgcmVxdWVzdC5vYmplY3QuY2xhc3NOYW1lID09PSAnX1VzZXInICYmXG4gICAgIXJlcXVlc3Qub2JqZWN0LmV4aXN0ZWQoKVxuICApIHtcbiAgICByZXFVc2VyID0gcmVxdWVzdC5vYmplY3Q7XG4gIH1cbiAgaWYgKG9wdGlvbnMucmVxdWlyZVVzZXIgJiYgIXJlcVVzZXIpIHtcbiAgICB0aHJvdyAnVmFsaWRhdGlvbiBmYWlsZWQuIFBsZWFzZSBsb2dpbiB0byBjb250aW51ZS4nO1xuICB9XG4gIGlmIChvcHRpb25zLnJlcXVpcmVNYXN0ZXIgJiYgIXJlcXVlc3QubWFzdGVyKSB7XG4gICAgdGhyb3cgJ1ZhbGlkYXRpb24gZmFpbGVkLiBNYXN0ZXIga2V5IGlzIHJlcXVpcmVkIHRvIGNvbXBsZXRlIHRoaXMgcmVxdWVzdC4nO1xuICB9XG4gIGxldCBwYXJhbXMgPSByZXF1ZXN0LnBhcmFtcyB8fCB7fTtcbiAgaWYgKHJlcXVlc3Qub2JqZWN0KSB7XG4gICAgcGFyYW1zID0gcmVxdWVzdC5vYmplY3QudG9KU09OKCk7XG4gIH1cbiAgY29uc3QgcmVxdWlyZWRQYXJhbSA9IGtleSA9PiB7XG4gICAgY29uc3QgdmFsdWUgPSBwYXJhbXNba2V5XTtcbiAgICBpZiAodmFsdWUgPT0gbnVsbCkge1xuICAgICAgdGhyb3cgYFZhbGlkYXRpb24gZmFpbGVkLiBQbGVhc2Ugc3BlY2lmeSBkYXRhIGZvciAke2tleX0uYDtcbiAgICB9XG4gIH07XG5cbiAgY29uc3QgdmFsaWRhdGVPcHRpb25zID0gKG9wdCwga2V5LCB2YWwpID0+IHtcbiAgICBsZXQgb3B0cyA9IG9wdC5vcHRpb25zO1xuICAgIGlmICh0eXBlb2Ygb3B0cyA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgcmVzdWx0ID0gb3B0cyh2YWwpO1xuICAgICAgICBpZiAoIXJlc3VsdCAmJiByZXN1bHQgIT0gbnVsbCkge1xuICAgICAgICAgIHRocm93IG9wdC5lcnJvciB8fCBgVmFsaWRhdGlvbiBmYWlsZWQuIEludmFsaWQgdmFsdWUgZm9yICR7a2V5fS5gO1xuICAgICAgICB9XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmICghZSkge1xuICAgICAgICAgIHRocm93IG9wdC5lcnJvciB8fCBgVmFsaWRhdGlvbiBmYWlsZWQuIEludmFsaWQgdmFsdWUgZm9yICR7a2V5fS5gO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhyb3cgb3B0LmVycm9yIHx8IGUubWVzc2FnZSB8fCBlO1xuICAgICAgfVxuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBpZiAoIUFycmF5LmlzQXJyYXkob3B0cykpIHtcbiAgICAgIG9wdHMgPSBbb3B0Lm9wdGlvbnNdO1xuICAgIH1cblxuICAgIGlmICghb3B0cy5pbmNsdWRlcyh2YWwpKSB7XG4gICAgICB0aHJvdyAoXG4gICAgICAgIG9wdC5lcnJvciB8fCBgVmFsaWRhdGlvbiBmYWlsZWQuIEludmFsaWQgb3B0aW9uIGZvciAke2tleX0uIEV4cGVjdGVkOiAke29wdHMuam9pbignLCAnKX1gXG4gICAgICApO1xuICAgIH1cbiAgfTtcblxuICBjb25zdCBnZXRUeXBlID0gZm4gPT4ge1xuICAgIGNvbnN0IG1hdGNoID0gZm4gJiYgZm4udG9TdHJpbmcoKS5tYXRjaCgvXlxccypmdW5jdGlvbiAoXFx3KykvKTtcbiAgICByZXR1cm4gKG1hdGNoID8gbWF0Y2hbMV0gOiAnJykudG9Mb3dlckNhc2UoKTtcbiAgfTtcbiAgaWYgKEFycmF5LmlzQXJyYXkob3B0aW9ucy5maWVsZHMpKSB7XG4gICAgZm9yIChjb25zdCBrZXkgb2Ygb3B0aW9ucy5maWVsZHMpIHtcbiAgICAgIHJlcXVpcmVkUGFyYW0oa2V5KTtcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgZm9yIChjb25zdCBrZXkgaW4gb3B0aW9ucy5maWVsZHMpIHtcbiAgICAgIGNvbnN0IG9wdCA9IG9wdGlvbnMuZmllbGRzW2tleV07XG4gICAgICBsZXQgdmFsID0gcGFyYW1zW2tleV07XG4gICAgICBpZiAodHlwZW9mIG9wdCA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgcmVxdWlyZWRQYXJhbShvcHQpO1xuICAgICAgfVxuICAgICAgaWYgKHR5cGVvZiBvcHQgPT09ICdvYmplY3QnKSB7XG4gICAgICAgIGlmIChvcHQuZGVmYXVsdCAhPSBudWxsICYmIHZhbCA9PSBudWxsKSB7XG4gICAgICAgICAgdmFsID0gb3B0LmRlZmF1bHQ7XG4gICAgICAgICAgcGFyYW1zW2tleV0gPSB2YWw7XG4gICAgICAgICAgaWYgKHJlcXVlc3Qub2JqZWN0KSB7XG4gICAgICAgICAgICByZXF1ZXN0Lm9iamVjdC5zZXQoa2V5LCB2YWwpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBpZiAob3B0LmNvbnN0YW50ICYmIHJlcXVlc3Qub2JqZWN0KSB7XG4gICAgICAgICAgaWYgKHJlcXVlc3Qub3JpZ2luYWwpIHtcbiAgICAgICAgICAgIHJlcXVlc3Qub2JqZWN0LnNldChrZXksIHJlcXVlc3Qub3JpZ2luYWwuZ2V0KGtleSkpO1xuICAgICAgICAgIH0gZWxzZSBpZiAob3B0LmRlZmF1bHQgIT0gbnVsbCkge1xuICAgICAgICAgICAgcmVxdWVzdC5vYmplY3Quc2V0KGtleSwgb3B0LmRlZmF1bHQpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBpZiAob3B0LnJlcXVpcmVkKSB7XG4gICAgICAgICAgcmVxdWlyZWRQYXJhbShrZXkpO1xuICAgICAgICB9XG4gICAgICAgIGlmIChvcHQudHlwZSkge1xuICAgICAgICAgIGNvbnN0IHR5cGUgPSBnZXRUeXBlKG9wdC50eXBlKTtcbiAgICAgICAgICBpZiAodHlwZSA9PSAnYXJyYXknICYmICFBcnJheS5pc0FycmF5KHZhbCkpIHtcbiAgICAgICAgICAgIHRocm93IGBWYWxpZGF0aW9uIGZhaWxlZC4gSW52YWxpZCB0eXBlIGZvciAke2tleX0uIEV4cGVjdGVkOiBhcnJheWA7XG4gICAgICAgICAgfSBlbHNlIGlmICh0eXBlb2YgdmFsICE9PSB0eXBlKSB7XG4gICAgICAgICAgICB0aHJvdyBgVmFsaWRhdGlvbiBmYWlsZWQuIEludmFsaWQgdHlwZSBmb3IgJHtrZXl9LiBFeHBlY3RlZDogJHt0eXBlfWA7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGlmIChvcHQub3B0aW9ucykge1xuICAgICAgICAgIHZhbGlkYXRlT3B0aW9ucyhvcHQsIGtleSwgdmFsKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgfVxuICBjb25zdCB1c2VyS2V5cyA9IG9wdGlvbnMucmVxdWlyZVVzZXJLZXlzIHx8IFtdO1xuICBpZiAoQXJyYXkuaXNBcnJheSh1c2VyS2V5cykpIHtcbiAgICBmb3IgKGNvbnN0IGtleSBvZiB1c2VyS2V5cykge1xuICAgICAgaWYgKCFyZXFVc2VyKSB7XG4gICAgICAgIHRocm93ICdQbGVhc2UgbG9naW4gdG8gbWFrZSB0aGlzIHJlcXVlc3QuJztcbiAgICAgIH1cblxuICAgICAgaWYgKHJlcVVzZXIuZ2V0KGtleSkgPT0gbnVsbCkge1xuICAgICAgICB0aHJvdyBgVmFsaWRhdGlvbiBmYWlsZWQuIFBsZWFzZSBzZXQgZGF0YSBmb3IgJHtrZXl9IG9uIHlvdXIgYWNjb3VudC5gO1xuICAgICAgfVxuICAgIH1cbiAgfSBlbHNlIGlmICh0eXBlb2YgdXNlcktleXMgPT09ICdvYmplY3QnKSB7XG4gICAgZm9yIChjb25zdCBrZXkgaW4gb3B0aW9ucy5yZXF1aXJlVXNlcktleXMpIHtcbiAgICAgIGNvbnN0IG9wdCA9IG9wdGlvbnMucmVxdWlyZVVzZXJLZXlzW2tleV07XG4gICAgICBpZiAob3B0Lm9wdGlvbnMpIHtcbiAgICAgICAgdmFsaWRhdGVPcHRpb25zKG9wdCwga2V5LCByZXFVc2VyLmdldChrZXkpKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn1cblxuLy8gVG8gYmUgdXNlZCBhcyBwYXJ0IG9mIHRoZSBwcm9taXNlIGNoYWluIHdoZW4gc2F2aW5nL2RlbGV0aW5nIGFuIG9iamVjdFxuLy8gV2lsbCByZXNvbHZlIHN1Y2Nlc3NmdWxseSBpZiBubyB0cmlnZ2VyIGlzIGNvbmZpZ3VyZWRcbi8vIFJlc29sdmVzIHRvIGFuIG9iamVjdCwgZW1wdHkgb3IgY29udGFpbmluZyBhbiBvYmplY3Qga2V5LiBBIGJlZm9yZVNhdmVcbi8vIHRyaWdnZXIgd2lsbCBzZXQgdGhlIG9iamVjdCBrZXkgdG8gdGhlIHJlc3QgZm9ybWF0IG9iamVjdCB0byBzYXZlLlxuLy8gb3JpZ2luYWxQYXJzZU9iamVjdCBpcyBvcHRpb25hbCwgd2Ugb25seSBuZWVkIHRoYXQgZm9yIGJlZm9yZS9hZnRlclNhdmUgZnVuY3Rpb25zXG5leHBvcnQgZnVuY3Rpb24gbWF5YmVSdW5UcmlnZ2VyKFxuICB0cmlnZ2VyVHlwZSxcbiAgYXV0aCxcbiAgcGFyc2VPYmplY3QsXG4gIG9yaWdpbmFsUGFyc2VPYmplY3QsXG4gIGNvbmZpZyxcbiAgY29udGV4dFxuKSB7XG4gIGlmICghcGFyc2VPYmplY3QpIHtcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHt9KTtcbiAgfVxuICByZXR1cm4gbmV3IFByb21pc2UoZnVuY3Rpb24gKHJlc29sdmUsIHJlamVjdCkge1xuICAgIHZhciB0cmlnZ2VyID0gZ2V0VHJpZ2dlcihwYXJzZU9iamVjdC5jbGFzc05hbWUsIHRyaWdnZXJUeXBlLCBjb25maWcuYXBwbGljYXRpb25JZCk7XG4gICAgaWYgKCF0cmlnZ2VyKSByZXR1cm4gcmVzb2x2ZSgpO1xuICAgIHZhciByZXF1ZXN0ID0gZ2V0UmVxdWVzdE9iamVjdChcbiAgICAgIHRyaWdnZXJUeXBlLFxuICAgICAgYXV0aCxcbiAgICAgIHBhcnNlT2JqZWN0LFxuICAgICAgb3JpZ2luYWxQYXJzZU9iamVjdCxcbiAgICAgIGNvbmZpZyxcbiAgICAgIGNvbnRleHRcbiAgICApO1xuICAgIHZhciB7IHN1Y2Nlc3MsIGVycm9yIH0gPSBnZXRSZXNwb25zZU9iamVjdChcbiAgICAgIHJlcXVlc3QsXG4gICAgICBvYmplY3QgPT4ge1xuICAgICAgICBsb2dUcmlnZ2VyU3VjY2Vzc0JlZm9yZUhvb2soXG4gICAgICAgICAgdHJpZ2dlclR5cGUsXG4gICAgICAgICAgcGFyc2VPYmplY3QuY2xhc3NOYW1lLFxuICAgICAgICAgIHBhcnNlT2JqZWN0LnRvSlNPTigpLFxuICAgICAgICAgIG9iamVjdCxcbiAgICAgICAgICBhdXRoXG4gICAgICAgICk7XG4gICAgICAgIGlmIChcbiAgICAgICAgICB0cmlnZ2VyVHlwZSA9PT0gVHlwZXMuYmVmb3JlU2F2ZSB8fFxuICAgICAgICAgIHRyaWdnZXJUeXBlID09PSBUeXBlcy5hZnRlclNhdmUgfHxcbiAgICAgICAgICB0cmlnZ2VyVHlwZSA9PT0gVHlwZXMuYmVmb3JlRGVsZXRlIHx8XG4gICAgICAgICAgdHJpZ2dlclR5cGUgPT09IFR5cGVzLmFmdGVyRGVsZXRlXG4gICAgICAgICkge1xuICAgICAgICAgIE9iamVjdC5hc3NpZ24oY29udGV4dCwgcmVxdWVzdC5jb250ZXh0KTtcbiAgICAgICAgfVxuICAgICAgICByZXNvbHZlKG9iamVjdCk7XG4gICAgICB9LFxuICAgICAgZXJyb3IgPT4ge1xuICAgICAgICBsb2dUcmlnZ2VyRXJyb3JCZWZvcmVIb29rKFxuICAgICAgICAgIHRyaWdnZXJUeXBlLFxuICAgICAgICAgIHBhcnNlT2JqZWN0LmNsYXNzTmFtZSxcbiAgICAgICAgICBwYXJzZU9iamVjdC50b0pTT04oKSxcbiAgICAgICAgICBhdXRoLFxuICAgICAgICAgIGVycm9yXG4gICAgICAgICk7XG4gICAgICAgIHJlamVjdChlcnJvcik7XG4gICAgICB9XG4gICAgKTtcblxuICAgIC8vIEFmdGVyU2F2ZSBhbmQgYWZ0ZXJEZWxldGUgdHJpZ2dlcnMgY2FuIHJldHVybiBhIHByb21pc2UsIHdoaWNoIGlmIHRoZXlcbiAgICAvLyBkbywgbmVlZHMgdG8gYmUgcmVzb2x2ZWQgYmVmb3JlIHRoaXMgcHJvbWlzZSBpcyByZXNvbHZlZCxcbiAgICAvLyBzbyB0cmlnZ2VyIGV4ZWN1dGlvbiBpcyBzeW5jZWQgd2l0aCBSZXN0V3JpdGUuZXhlY3V0ZSgpIGNhbGwuXG4gICAgLy8gSWYgdHJpZ2dlcnMgZG8gbm90IHJldHVybiBhIHByb21pc2UsIHRoZXkgY2FuIHJ1biBhc3luYyBjb2RlIHBhcmFsbGVsXG4gICAgLy8gdG8gdGhlIFJlc3RXcml0ZS5leGVjdXRlKCkgY2FsbC5cbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKClcbiAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgcmV0dXJuIG1heWJlUnVuVmFsaWRhdG9yKHJlcXVlc3QsIGAke3RyaWdnZXJUeXBlfS4ke3BhcnNlT2JqZWN0LmNsYXNzTmFtZX1gKTtcbiAgICAgIH0pXG4gICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgIGlmIChyZXF1ZXN0LnNraXBXaXRoTWFzdGVyS2V5KSB7XG4gICAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgICAgICB9XG4gICAgICAgIGNvbnN0IHByb21pc2UgPSB0cmlnZ2VyKHJlcXVlc3QpO1xuICAgICAgICBpZiAoXG4gICAgICAgICAgdHJpZ2dlclR5cGUgPT09IFR5cGVzLmFmdGVyU2F2ZSB8fFxuICAgICAgICAgIHRyaWdnZXJUeXBlID09PSBUeXBlcy5hZnRlckRlbGV0ZSB8fFxuICAgICAgICAgIHRyaWdnZXJUeXBlID09PSBUeXBlcy5hZnRlckxvZ2luXG4gICAgICAgICkge1xuICAgICAgICAgIGxvZ1RyaWdnZXJBZnRlckhvb2sodHJpZ2dlclR5cGUsIHBhcnNlT2JqZWN0LmNsYXNzTmFtZSwgcGFyc2VPYmplY3QudG9KU09OKCksIGF1dGgpO1xuICAgICAgICB9XG4gICAgICAgIC8vIGJlZm9yZVNhdmUgaXMgZXhwZWN0ZWQgdG8gcmV0dXJuIG51bGwgKG5vdGhpbmcpXG4gICAgICAgIGlmICh0cmlnZ2VyVHlwZSA9PT0gVHlwZXMuYmVmb3JlU2F2ZSkge1xuICAgICAgICAgIGlmIChwcm9taXNlICYmIHR5cGVvZiBwcm9taXNlLnRoZW4gPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgICAgIHJldHVybiBwcm9taXNlLnRoZW4ocmVzcG9uc2UgPT4ge1xuICAgICAgICAgICAgICAvLyByZXNwb25zZS5vYmplY3QgbWF5IGNvbWUgZnJvbSBleHByZXNzIHJvdXRpbmcgYmVmb3JlIGhvb2tcbiAgICAgICAgICAgICAgaWYgKHJlc3BvbnNlICYmIHJlc3BvbnNlLm9iamVjdCkge1xuICAgICAgICAgICAgICAgIHJldHVybiByZXNwb25zZTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBwcm9taXNlO1xuICAgICAgfSlcbiAgICAgIC50aGVuKHN1Y2Nlc3MsIGVycm9yKTtcbiAgfSk7XG59XG5cbi8vIENvbnZlcnRzIGEgUkVTVC1mb3JtYXQgb2JqZWN0IHRvIGEgUGFyc2UuT2JqZWN0XG4vLyBkYXRhIGlzIGVpdGhlciBjbGFzc05hbWUgb3IgYW4gb2JqZWN0XG5leHBvcnQgZnVuY3Rpb24gaW5mbGF0ZShkYXRhLCByZXN0T2JqZWN0KSB7XG4gIHZhciBjb3B5ID0gdHlwZW9mIGRhdGEgPT0gJ29iamVjdCcgPyBkYXRhIDogeyBjbGFzc05hbWU6IGRhdGEgfTtcbiAgZm9yICh2YXIga2V5IGluIHJlc3RPYmplY3QpIHtcbiAgICBjb3B5W2tleV0gPSByZXN0T2JqZWN0W2tleV07XG4gIH1cbiAgcmV0dXJuIFBhcnNlLk9iamVjdC5mcm9tSlNPTihjb3B5KTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHJ1bkxpdmVRdWVyeUV2ZW50SGFuZGxlcnMoZGF0YSwgYXBwbGljYXRpb25JZCA9IFBhcnNlLmFwcGxpY2F0aW9uSWQpIHtcbiAgaWYgKCFfdHJpZ2dlclN0b3JlIHx8ICFfdHJpZ2dlclN0b3JlW2FwcGxpY2F0aW9uSWRdIHx8ICFfdHJpZ2dlclN0b3JlW2FwcGxpY2F0aW9uSWRdLkxpdmVRdWVyeSkge1xuICAgIHJldHVybjtcbiAgfVxuICBfdHJpZ2dlclN0b3JlW2FwcGxpY2F0aW9uSWRdLkxpdmVRdWVyeS5mb3JFYWNoKGhhbmRsZXIgPT4gaGFuZGxlcihkYXRhKSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRSZXF1ZXN0RmlsZU9iamVjdCh0cmlnZ2VyVHlwZSwgYXV0aCwgZmlsZU9iamVjdCwgY29uZmlnKSB7XG4gIGNvbnN0IHJlcXVlc3QgPSB7XG4gICAgLi4uZmlsZU9iamVjdCxcbiAgICB0cmlnZ2VyTmFtZTogdHJpZ2dlclR5cGUsXG4gICAgbWFzdGVyOiBmYWxzZSxcbiAgICBsb2c6IGNvbmZpZy5sb2dnZXJDb250cm9sbGVyLFxuICAgIGhlYWRlcnM6IGNvbmZpZy5oZWFkZXJzLFxuICAgIGlwOiBjb25maWcuaXAsXG4gIH07XG5cbiAgaWYgKCFhdXRoKSB7XG4gICAgcmV0dXJuIHJlcXVlc3Q7XG4gIH1cbiAgaWYgKGF1dGguaXNNYXN0ZXIpIHtcbiAgICByZXF1ZXN0WydtYXN0ZXInXSA9IHRydWU7XG4gIH1cbiAgaWYgKGF1dGgudXNlcikge1xuICAgIHJlcXVlc3RbJ3VzZXInXSA9IGF1dGgudXNlcjtcbiAgfVxuICBpZiAoYXV0aC5pbnN0YWxsYXRpb25JZCkge1xuICAgIHJlcXVlc3RbJ2luc3RhbGxhdGlvbklkJ10gPSBhdXRoLmluc3RhbGxhdGlvbklkO1xuICB9XG4gIHJldHVybiByZXF1ZXN0O1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gbWF5YmVSdW5GaWxlVHJpZ2dlcih0cmlnZ2VyVHlwZSwgZmlsZU9iamVjdCwgY29uZmlnLCBhdXRoKSB7XG4gIGNvbnN0IGZpbGVUcmlnZ2VyID0gZ2V0RmlsZVRyaWdnZXIodHJpZ2dlclR5cGUsIGNvbmZpZy5hcHBsaWNhdGlvbklkKTtcbiAgaWYgKHR5cGVvZiBmaWxlVHJpZ2dlciA9PT0gJ2Z1bmN0aW9uJykge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCByZXF1ZXN0ID0gZ2V0UmVxdWVzdEZpbGVPYmplY3QodHJpZ2dlclR5cGUsIGF1dGgsIGZpbGVPYmplY3QsIGNvbmZpZyk7XG4gICAgICBhd2FpdCBtYXliZVJ1blZhbGlkYXRvcihyZXF1ZXN0LCBgJHt0cmlnZ2VyVHlwZX0uJHtGaWxlQ2xhc3NOYW1lfWApO1xuICAgICAgaWYgKHJlcXVlc3Quc2tpcFdpdGhNYXN0ZXJLZXkpIHtcbiAgICAgICAgcmV0dXJuIGZpbGVPYmplY3Q7XG4gICAgICB9XG4gICAgICBjb25zdCByZXN1bHQgPSBhd2FpdCBmaWxlVHJpZ2dlcihyZXF1ZXN0KTtcbiAgICAgIGxvZ1RyaWdnZXJTdWNjZXNzQmVmb3JlSG9vayhcbiAgICAgICAgdHJpZ2dlclR5cGUsXG4gICAgICAgICdQYXJzZS5GaWxlJyxcbiAgICAgICAgeyAuLi5maWxlT2JqZWN0LmZpbGUudG9KU09OKCksIGZpbGVTaXplOiBmaWxlT2JqZWN0LmZpbGVTaXplIH0sXG4gICAgICAgIHJlc3VsdCxcbiAgICAgICAgYXV0aFxuICAgICAgKTtcbiAgICAgIHJldHVybiByZXN1bHQgfHwgZmlsZU9iamVjdDtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nVHJpZ2dlckVycm9yQmVmb3JlSG9vayhcbiAgICAgICAgdHJpZ2dlclR5cGUsXG4gICAgICAgICdQYXJzZS5GaWxlJyxcbiAgICAgICAgeyAuLi5maWxlT2JqZWN0LmZpbGUudG9KU09OKCksIGZpbGVTaXplOiBmaWxlT2JqZWN0LmZpbGVTaXplIH0sXG4gICAgICAgIGF1dGgsXG4gICAgICAgIGVycm9yXG4gICAgICApO1xuICAgICAgdGhyb3cgZXJyb3I7XG4gICAgfVxuICB9XG4gIHJldHVybiBmaWxlT2JqZWN0O1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gbWF5YmVSdW5Db25uZWN0VHJpZ2dlcih0cmlnZ2VyVHlwZSwgcmVxdWVzdCkge1xuICBjb25zdCB0cmlnZ2VyID0gZ2V0VHJpZ2dlcihDb25uZWN0Q2xhc3NOYW1lLCB0cmlnZ2VyVHlwZSwgUGFyc2UuYXBwbGljYXRpb25JZCk7XG4gIGlmICghdHJpZ2dlcikge1xuICAgIHJldHVybjtcbiAgfVxuICByZXF1ZXN0LnVzZXIgPSBhd2FpdCB1c2VyRm9yU2Vzc2lvblRva2VuKHJlcXVlc3Quc2Vzc2lvblRva2VuKTtcbiAgYXdhaXQgbWF5YmVSdW5WYWxpZGF0b3IocmVxdWVzdCwgYCR7dHJpZ2dlclR5cGV9LiR7Q29ubmVjdENsYXNzTmFtZX1gKTtcbiAgaWYgKHJlcXVlc3Quc2tpcFdpdGhNYXN0ZXJLZXkpIHtcbiAgICByZXR1cm47XG4gIH1cbiAgcmV0dXJuIHRyaWdnZXIocmVxdWVzdCk7XG59XG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBtYXliZVJ1blN1YnNjcmliZVRyaWdnZXIodHJpZ2dlclR5cGUsIGNsYXNzTmFtZSwgcmVxdWVzdCkge1xuICBjb25zdCB0cmlnZ2VyID0gZ2V0VHJpZ2dlcihjbGFzc05hbWUsIHRyaWdnZXJUeXBlLCBQYXJzZS5hcHBsaWNhdGlvbklkKTtcbiAgaWYgKCF0cmlnZ2VyKSB7XG4gICAgcmV0dXJuO1xuICB9XG4gIGNvbnN0IHBhcnNlUXVlcnkgPSBuZXcgUGFyc2UuUXVlcnkoY2xhc3NOYW1lKTtcbiAgcGFyc2VRdWVyeS53aXRoSlNPTihyZXF1ZXN0LnF1ZXJ5KTtcbiAgcmVxdWVzdC5xdWVyeSA9IHBhcnNlUXVlcnk7XG4gIHJlcXVlc3QudXNlciA9IGF3YWl0IHVzZXJGb3JTZXNzaW9uVG9rZW4ocmVxdWVzdC5zZXNzaW9uVG9rZW4pO1xuICBhd2FpdCBtYXliZVJ1blZhbGlkYXRvcihyZXF1ZXN0LCBgJHt0cmlnZ2VyVHlwZX0uJHtjbGFzc05hbWV9YCk7XG4gIGlmIChyZXF1ZXN0LnNraXBXaXRoTWFzdGVyS2V5KSB7XG4gICAgcmV0dXJuO1xuICB9XG4gIGF3YWl0IHRyaWdnZXIocmVxdWVzdCk7XG4gIGNvbnN0IHF1ZXJ5ID0gcmVxdWVzdC5xdWVyeS50b0pTT04oKTtcbiAgaWYgKHF1ZXJ5LmtleXMpIHtcbiAgICBxdWVyeS5maWVsZHMgPSBxdWVyeS5rZXlzLnNwbGl0KCcsJyk7XG4gIH1cbiAgcmVxdWVzdC5xdWVyeSA9IHF1ZXJ5O1xufVxuXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gbWF5YmVSdW5BZnRlckV2ZW50VHJpZ2dlcih0cmlnZ2VyVHlwZSwgY2xhc3NOYW1lLCByZXF1ZXN0KSB7XG4gIGNvbnN0IHRyaWdnZXIgPSBnZXRUcmlnZ2VyKGNsYXNzTmFtZSwgdHJpZ2dlclR5cGUsIFBhcnNlLmFwcGxpY2F0aW9uSWQpO1xuICBpZiAoIXRyaWdnZXIpIHtcbiAgICByZXR1cm47XG4gIH1cbiAgaWYgKHJlcXVlc3Qub2JqZWN0KSB7XG4gICAgcmVxdWVzdC5vYmplY3QgPSBQYXJzZS5PYmplY3QuZnJvbUpTT04ocmVxdWVzdC5vYmplY3QpO1xuICB9XG4gIGlmIChyZXF1ZXN0Lm9yaWdpbmFsKSB7XG4gICAgcmVxdWVzdC5vcmlnaW5hbCA9IFBhcnNlLk9iamVjdC5mcm9tSlNPTihyZXF1ZXN0Lm9yaWdpbmFsKTtcbiAgfVxuICByZXF1ZXN0LnVzZXIgPSBhd2FpdCB1c2VyRm9yU2Vzc2lvblRva2VuKHJlcXVlc3Quc2Vzc2lvblRva2VuKTtcbiAgYXdhaXQgbWF5YmVSdW5WYWxpZGF0b3IocmVxdWVzdCwgYCR7dHJpZ2dlclR5cGV9LiR7Y2xhc3NOYW1lfWApO1xuICBpZiAocmVxdWVzdC5za2lwV2l0aE1hc3RlcktleSkge1xuICAgIHJldHVybjtcbiAgfVxuICByZXR1cm4gdHJpZ2dlcihyZXF1ZXN0KTtcbn1cblxuYXN5bmMgZnVuY3Rpb24gdXNlckZvclNlc3Npb25Ub2tlbihzZXNzaW9uVG9rZW4pIHtcbiAgaWYgKCFzZXNzaW9uVG9rZW4pIHtcbiAgICByZXR1cm47XG4gIH1cbiAgY29uc3QgcSA9IG5ldyBQYXJzZS5RdWVyeSgnX1Nlc3Npb24nKTtcbiAgcS5lcXVhbFRvKCdzZXNzaW9uVG9rZW4nLCBzZXNzaW9uVG9rZW4pO1xuICBxLmluY2x1ZGUoJ3VzZXInKTtcbiAgY29uc3Qgc2Vzc2lvbiA9IGF3YWl0IHEuZmlyc3QoeyB1c2VNYXN0ZXJLZXk6IHRydWUgfSk7XG4gIGlmICghc2Vzc2lvbikge1xuICAgIHJldHVybjtcbiAgfVxuICByZXR1cm4gc2Vzc2lvbi5nZXQoJ3VzZXInKTtcbn1cbiJdfQ==