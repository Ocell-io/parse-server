"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.classNameIsValid = classNameIsValid;
exports.fieldNameIsValid = fieldNameIsValid;
exports.invalidClassNameMessage = invalidClassNameMessage;
exports.buildMergedSchemaObject = buildMergedSchemaObject;
exports.VolatileClassesSchemas = exports.convertSchemaToAdapterSchema = exports.defaultColumns = exports.systemClasses = exports.load = exports.SchemaController = exports.default = void 0;

var _StorageAdapter = require("../Adapters/Storage/StorageAdapter");

var _SchemaCache = _interopRequireDefault(require("../Adapters/Cache/SchemaCache"));

var _DatabaseController = _interopRequireDefault(require("./DatabaseController"));

var _Config = _interopRequireDefault(require("../Config"));

var _deepcopy = _interopRequireDefault(require("deepcopy"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _extends() { _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; }; return _extends.apply(this, arguments); }

// This class handles schema validation, persistence, and modification.
//
// Each individual Schema object should be immutable. The helpers to
// do things with the Schema just return a new schema when the schema
// is changed.
//
// The canonical place to store this Schema is in the database itself,
// in a _SCHEMA collection. This is not the right way to do it for an
// open source framework, but it's backward compatible, so we're
// keeping it this way for now.
//
// In API-handling code, you should only use the Schema class via the
// DatabaseController. This will let us replace the schema logic for
// different databases.
// TODO: hide all schema logic inside the database adapter.
// -disable-next
const Parse = require('parse/node').Parse;

const defaultColumns = Object.freeze({
  // Contain the default columns for every parse object type (except _Join collection)
  _Default: {
    objectId: {
      type: 'String'
    },
    createdAt: {
      type: 'Date'
    },
    updatedAt: {
      type: 'Date'
    },
    ACL: {
      type: 'ACL'
    }
  },
  // The additional default columns for the _User collection (in addition to DefaultCols)
  _User: {
    username: {
      type: 'String'
    },
    password: {
      type: 'String'
    },
    email: {
      type: 'String'
    },
    emailVerified: {
      type: 'Boolean'
    },
    authData: {
      type: 'Object'
    }
  },
  // The additional default columns for the _Installation collection (in addition to DefaultCols)
  _Installation: {
    installationId: {
      type: 'String'
    },
    deviceToken: {
      type: 'String'
    },
    channels: {
      type: 'Array'
    },
    deviceType: {
      type: 'String'
    },
    pushType: {
      type: 'String'
    },
    GCMSenderId: {
      type: 'String'
    },
    timeZone: {
      type: 'String'
    },
    localeIdentifier: {
      type: 'String'
    },
    badge: {
      type: 'Number'
    },
    appVersion: {
      type: 'String'
    },
    appName: {
      type: 'String'
    },
    appIdentifier: {
      type: 'String'
    },
    parseVersion: {
      type: 'String'
    }
  },
  // The additional default columns for the _Role collection (in addition to DefaultCols)
  _Role: {
    name: {
      type: 'String'
    },
    users: {
      type: 'Relation',
      targetClass: '_User'
    },
    roles: {
      type: 'Relation',
      targetClass: '_Role'
    }
  },
  // The additional default columns for the _Session collection (in addition to DefaultCols)
  _Session: {
    restricted: {
      type: 'Boolean'
    },
    user: {
      type: 'Pointer',
      targetClass: '_User'
    },
    installationId: {
      type: 'String'
    },
    sessionToken: {
      type: 'String'
    },
    expiresAt: {
      type: 'Date'
    },
    createdWith: {
      type: 'Object'
    }
  },
  _Product: {
    productIdentifier: {
      type: 'String'
    },
    download: {
      type: 'File'
    },
    downloadName: {
      type: 'String'
    },
    icon: {
      type: 'File'
    },
    order: {
      type: 'Number'
    },
    title: {
      type: 'String'
    },
    subtitle: {
      type: 'String'
    }
  },
  _PushStatus: {
    pushTime: {
      type: 'String'
    },
    source: {
      type: 'String'
    },
    // rest or webui
    query: {
      type: 'String'
    },
    // the stringified JSON query
    payload: {
      type: 'String'
    },
    // the stringified JSON payload,
    title: {
      type: 'String'
    },
    expiry: {
      type: 'Number'
    },
    expiration_interval: {
      type: 'Number'
    },
    status: {
      type: 'String'
    },
    numSent: {
      type: 'Number'
    },
    numFailed: {
      type: 'Number'
    },
    pushHash: {
      type: 'String'
    },
    errorMessage: {
      type: 'Object'
    },
    sentPerType: {
      type: 'Object'
    },
    failedPerType: {
      type: 'Object'
    },
    sentPerUTCOffset: {
      type: 'Object'
    },
    failedPerUTCOffset: {
      type: 'Object'
    },
    count: {
      type: 'Number'
    } // tracks # of batches queued and pending

  },
  _JobStatus: {
    jobName: {
      type: 'String'
    },
    source: {
      type: 'String'
    },
    status: {
      type: 'String'
    },
    message: {
      type: 'String'
    },
    params: {
      type: 'Object'
    },
    // params received when calling the job
    finishedAt: {
      type: 'Date'
    }
  },
  _JobSchedule: {
    jobName: {
      type: 'String'
    },
    description: {
      type: 'String'
    },
    params: {
      type: 'String'
    },
    startAfter: {
      type: 'String'
    },
    daysOfWeek: {
      type: 'Array'
    },
    timeOfDay: {
      type: 'String'
    },
    lastRun: {
      type: 'Number'
    },
    repeatMinutes: {
      type: 'Number'
    }
  },
  _Hooks: {
    functionName: {
      type: 'String'
    },
    className: {
      type: 'String'
    },
    triggerName: {
      type: 'String'
    },
    url: {
      type: 'String'
    }
  },
  _GlobalConfig: {
    objectId: {
      type: 'String'
    },
    params: {
      type: 'Object'
    },
    masterKeyOnly: {
      type: 'Object'
    }
  },
  _GraphQLConfig: {
    objectId: {
      type: 'String'
    },
    config: {
      type: 'Object'
    }
  },
  _Audience: {
    objectId: {
      type: 'String'
    },
    name: {
      type: 'String'
    },
    query: {
      type: 'String'
    },
    //storing query as JSON string to prevent "Nested keys should not contain the '$' or '.' characters" error
    lastUsed: {
      type: 'Date'
    },
    timesUsed: {
      type: 'Number'
    }
  },
  _Idempotency: {
    reqId: {
      type: 'String'
    },
    expire: {
      type: 'Date'
    }
  }
});
exports.defaultColumns = defaultColumns;
const requiredColumns = Object.freeze({
  _Product: ['productIdentifier', 'icon', 'order', 'title', 'subtitle'],
  _Role: ['name', 'ACL']
});
const invalidColumns = ['length'];
const systemClasses = Object.freeze(['_User', '_Installation', '_Role', '_Session', '_Product', '_PushStatus', '_JobStatus', '_JobSchedule', '_Audience', '_Idempotency']);
exports.systemClasses = systemClasses;
const volatileClasses = Object.freeze(['_JobStatus', '_PushStatus', '_Hooks', '_GlobalConfig', '_GraphQLConfig', '_JobSchedule', '_Audience', '_Idempotency']); // Anything that start with role

const roleRegex = /^role:.*/; // Anything that starts with userField (allowed for protected fields only)

const protectedFieldsPointerRegex = /^userField:.*/; // * permission

const publicRegex = /^\*$/;
const authenticatedRegex = /^authenticated$/;
const requiresAuthenticationRegex = /^requiresAuthentication$/;
const clpPointerRegex = /^pointerFields$/; // regex for validating entities in protectedFields object

const protectedFieldsRegex = Object.freeze([protectedFieldsPointerRegex, publicRegex, authenticatedRegex, roleRegex]); // clp regex

const clpFieldsRegex = Object.freeze([clpPointerRegex, publicRegex, requiresAuthenticationRegex, roleRegex]);

function validatePermissionKey(key, userIdRegExp) {
  let matchesSome = false;

  for (const regEx of clpFieldsRegex) {
    if (key.match(regEx) !== null) {
      matchesSome = true;
      break;
    }
  } // userId depends on startup options so it's dynamic


  const valid = matchesSome || key.match(userIdRegExp) !== null;

  if (!valid) {
    throw new Parse.Error(Parse.Error.INVALID_JSON, `'${key}' is not a valid key for class level permissions`);
  }
}

function validateProtectedFieldsKey(key, userIdRegExp) {
  let matchesSome = false;

  for (const regEx of protectedFieldsRegex) {
    if (key.match(regEx) !== null) {
      matchesSome = true;
      break;
    }
  } // userId regex depends on launch options so it's dynamic


  const valid = matchesSome || key.match(userIdRegExp) !== null;

  if (!valid) {
    throw new Parse.Error(Parse.Error.INVALID_JSON, `'${key}' is not a valid key for class level permissions`);
  }
}

const CLPValidKeys = Object.freeze(['find', 'count', 'get', 'create', 'update', 'delete', 'addField', 'readUserFields', 'writeUserFields', 'protectedFields']); // validation before setting class-level permissions on collection

function validateCLP(perms, fields, userIdRegExp) {
  if (!perms) {
    return;
  }

  for (const operationKey in perms) {
    if (CLPValidKeys.indexOf(operationKey) == -1) {
      throw new Parse.Error(Parse.Error.INVALID_JSON, `${operationKey} is not a valid operation for class level permissions`);
    }

    const operation = perms[operationKey]; // proceed with next operationKey
    // throws when root fields are of wrong type

    validateCLPjson(operation, operationKey);

    if (operationKey === 'readUserFields' || operationKey === 'writeUserFields') {
      // validate grouped pointer permissions
      // must be an array with field names
      for (const fieldName of operation) {
        validatePointerPermission(fieldName, fields, operationKey);
      } // readUserFields and writerUserFields do not have nesdted fields
      // proceed with next operationKey


      continue;
    } // validate protected fields


    if (operationKey === 'protectedFields') {
      for (const entity in operation) {
        // throws on unexpected key
        validateProtectedFieldsKey(entity, userIdRegExp);
        const protectedFields = operation[entity];

        if (!Array.isArray(protectedFields)) {
          throw new Parse.Error(Parse.Error.INVALID_JSON, `'${protectedFields}' is not a valid value for protectedFields[${entity}] - expected an array.`);
        } // if the field is in form of array


        for (const field of protectedFields) {
          // do not alloow to protect default fields
          if (defaultColumns._Default[field]) {
            throw new Parse.Error(Parse.Error.INVALID_JSON, `Default field '${field}' can not be protected`);
          } // field should exist on collection


          if (!Object.prototype.hasOwnProperty.call(fields, field)) {
            throw new Parse.Error(Parse.Error.INVALID_JSON, `Field '${field}' in protectedFields:${entity} does not exist`);
          }
        }
      } // proceed with next operationKey


      continue;
    } // validate other fields
    // Entity can be:
    // "*" - Public,
    // "requiresAuthentication" - authenticated users,
    // "objectId" - _User id,
    // "role:rolename",
    // "pointerFields" - array of field names containing pointers to users


    for (const entity in operation) {
      // throws on unexpected key
      validatePermissionKey(entity, userIdRegExp); // entity can be either:
      // "pointerFields": string[]

      if (entity === 'pointerFields') {
        const pointerFields = operation[entity];

        if (Array.isArray(pointerFields)) {
          for (const pointerField of pointerFields) {
            validatePointerPermission(pointerField, fields, operation);
          }
        } else {
          throw new Parse.Error(Parse.Error.INVALID_JSON, `'${pointerFields}' is not a valid value for ${operationKey}[${entity}] - expected an array.`);
        } // proceed with next entity key


        continue;
      } // or [entity]: boolean


      const permit = operation[entity];

      if (permit !== true) {
        throw new Parse.Error(Parse.Error.INVALID_JSON, `'${permit}' is not a valid value for class level permissions ${operationKey}:${entity}:${permit}`);
      }
    }
  }
}

function validateCLPjson(operation, operationKey) {
  if (operationKey === 'readUserFields' || operationKey === 'writeUserFields') {
    if (!Array.isArray(operation)) {
      throw new Parse.Error(Parse.Error.INVALID_JSON, `'${operation}' is not a valid value for class level permissions ${operationKey} - must be an array`);
    }
  } else {
    if (typeof operation === 'object' && operation !== null) {
      // ok to proceed
      return;
    } else {
      throw new Parse.Error(Parse.Error.INVALID_JSON, `'${operation}' is not a valid value for class level permissions ${operationKey} - must be an object`);
    }
  }
}

function validatePointerPermission(fieldName, fields, operation) {
  // Uses collection schema to ensure the field is of type:
  // - Pointer<_User> (pointers)
  // - Array
  //
  //    It's not possible to enforce type on Array's items in schema
  //  so we accept any Array field, and later when applying permissions
  //  only items that are pointers to _User are considered.
  if (!(fields[fieldName] && (fields[fieldName].type == 'Pointer' && fields[fieldName].targetClass == '_User' || fields[fieldName].type == 'Array'))) {
    throw new Parse.Error(Parse.Error.INVALID_JSON, `'${fieldName}' is not a valid column for class level pointer permissions ${operation}`);
  }
}

const joinClassRegex = /^_Join:[A-Za-z0-9_]+:[A-Za-z0-9_]+/;
const classAndFieldRegex = /^[A-Za-z][A-Za-z0-9_]*$/;

function classNameIsValid(className) {
  // Valid classes must:
  return (// Be one of _User, _Installation, _Role, _Session OR
    systemClasses.indexOf(className) > -1 || // Be a join table OR
    joinClassRegex.test(className) || // Include only alpha-numeric and underscores, and not start with an underscore or number
    fieldNameIsValid(className, className)
  );
} // Valid fields must be alpha-numeric, and not start with an underscore or number
// must not be a reserved key


function fieldNameIsValid(fieldName, className) {
  if (className && className !== '_Hooks') {
    if (fieldName === 'className') {
      return false;
    }
  }

  return classAndFieldRegex.test(fieldName) && !invalidColumns.includes(fieldName);
} // Checks that it's not trying to clobber one of the default fields of the class.


function fieldNameIsValidForClass(fieldName, className) {
  if (!fieldNameIsValid(fieldName, className)) {
    return false;
  }

  if (defaultColumns._Default[fieldName]) {
    return false;
  }

  if (defaultColumns[className] && defaultColumns[className][fieldName]) {
    return false;
  }

  return true;
}

function invalidClassNameMessage(className) {
  return 'Invalid classname: ' + className + ', classnames can only have alphanumeric characters and _, and must start with an alpha character ';
}

const invalidJsonError = new Parse.Error(Parse.Error.INVALID_JSON, 'invalid JSON');
const validNonRelationOrPointerTypes = ['Number', 'String', 'Boolean', 'Date', 'Object', 'Array', 'GeoPoint', 'File', 'Bytes', 'Polygon']; // Returns an error suitable for throwing if the type is invalid

const fieldTypeIsInvalid = ({
  type,
  targetClass
}) => {
  if (['Pointer', 'Relation'].indexOf(type) >= 0) {
    if (!targetClass) {
      return new Parse.Error(135, `type ${type} needs a class name`);
    } else if (typeof targetClass !== 'string') {
      return invalidJsonError;
    } else if (!classNameIsValid(targetClass)) {
      return new Parse.Error(Parse.Error.INVALID_CLASS_NAME, invalidClassNameMessage(targetClass));
    } else {
      return undefined;
    }
  }

  if (typeof type !== 'string') {
    return invalidJsonError;
  }

  if (validNonRelationOrPointerTypes.indexOf(type) < 0) {
    return new Parse.Error(Parse.Error.INCORRECT_TYPE, `invalid field type: ${type}`);
  }

  return undefined;
};

const convertSchemaToAdapterSchema = schema => {
  schema = injectDefaultSchema(schema);
  delete schema.fields.ACL;
  schema.fields._rperm = {
    type: 'Array'
  };
  schema.fields._wperm = {
    type: 'Array'
  };

  if (schema.className === '_User') {
    delete schema.fields.password;
    schema.fields._hashed_password = {
      type: 'String'
    };
  }

  return schema;
};

exports.convertSchemaToAdapterSchema = convertSchemaToAdapterSchema;

const convertAdapterSchemaToParseSchema = (_ref) => {
  let schema = _extends({}, _ref);

  delete schema.fields._rperm;
  delete schema.fields._wperm;
  schema.fields.ACL = {
    type: 'ACL'
  };

  if (schema.className === '_User') {
    delete schema.fields.authData; //Auth data is implicit

    delete schema.fields._hashed_password;
    schema.fields.password = {
      type: 'String'
    };
  }

  if (schema.indexes && Object.keys(schema.indexes).length === 0) {
    delete schema.indexes;
  }

  return schema;
};

class SchemaData {
  constructor(allSchemas = [], protectedFields = {}) {
    this.__data = {};
    this.__protectedFields = protectedFields;
    allSchemas.forEach(schema => {
      if (volatileClasses.includes(schema.className)) {
        return;
      }

      Object.defineProperty(this, schema.className, {
        get: () => {
          if (!this.__data[schema.className]) {
            const data = {};
            data.fields = injectDefaultSchema(schema).fields;
            data.classLevelPermissions = (0, _deepcopy.default)(schema.classLevelPermissions);
            data.indexes = schema.indexes;
            const classProtectedFields = this.__protectedFields[schema.className];

            if (classProtectedFields) {
              for (const key in classProtectedFields) {
                const unq = new Set([...(data.classLevelPermissions.protectedFields[key] || []), ...classProtectedFields[key]]);
                data.classLevelPermissions.protectedFields[key] = Array.from(unq);
              }
            }

            this.__data[schema.className] = data;
          }

          return this.__data[schema.className];
        }
      });
    }); // Inject the in-memory classes

    volatileClasses.forEach(className => {
      Object.defineProperty(this, className, {
        get: () => {
          if (!this.__data[className]) {
            const schema = injectDefaultSchema({
              className,
              fields: {},
              classLevelPermissions: {}
            });
            const data = {};
            data.fields = schema.fields;
            data.classLevelPermissions = schema.classLevelPermissions;
            data.indexes = schema.indexes;
            this.__data[className] = data;
          }

          return this.__data[className];
        }
      });
    });
  }

}

const injectDefaultSchema = ({
  className,
  fields,
  classLevelPermissions,
  indexes
}) => {
  const defaultSchema = {
    className,
    fields: _objectSpread(_objectSpread(_objectSpread({}, defaultColumns._Default), defaultColumns[className] || {}), fields),
    classLevelPermissions
  };

  if (indexes && Object.keys(indexes).length !== 0) {
    defaultSchema.indexes = indexes;
  }

  return defaultSchema;
};

const _HooksSchema = {
  className: '_Hooks',
  fields: defaultColumns._Hooks
};
const _GlobalConfigSchema = {
  className: '_GlobalConfig',
  fields: defaultColumns._GlobalConfig
};
const _GraphQLConfigSchema = {
  className: '_GraphQLConfig',
  fields: defaultColumns._GraphQLConfig
};

const _PushStatusSchema = convertSchemaToAdapterSchema(injectDefaultSchema({
  className: '_PushStatus',
  fields: {},
  classLevelPermissions: {}
}));

const _JobStatusSchema = convertSchemaToAdapterSchema(injectDefaultSchema({
  className: '_JobStatus',
  fields: {},
  classLevelPermissions: {}
}));

const _JobScheduleSchema = convertSchemaToAdapterSchema(injectDefaultSchema({
  className: '_JobSchedule',
  fields: {},
  classLevelPermissions: {}
}));

const _AudienceSchema = convertSchemaToAdapterSchema(injectDefaultSchema({
  className: '_Audience',
  fields: defaultColumns._Audience,
  classLevelPermissions: {}
}));

const _IdempotencySchema = convertSchemaToAdapterSchema(injectDefaultSchema({
  className: '_Idempotency',
  fields: defaultColumns._Idempotency,
  classLevelPermissions: {}
}));

const VolatileClassesSchemas = [_HooksSchema, _JobStatusSchema, _JobScheduleSchema, _PushStatusSchema, _GlobalConfigSchema, _GraphQLConfigSchema, _AudienceSchema, _IdempotencySchema];
exports.VolatileClassesSchemas = VolatileClassesSchemas;

const dbTypeMatchesObjectType = (dbType, objectType) => {
  if (dbType.type !== objectType.type) return false;
  if (dbType.targetClass !== objectType.targetClass) return false;
  if (dbType === objectType.type) return true;
  if (dbType.type === objectType.type) return true;
  return false;
};

const typeToString = type => {
  if (typeof type === 'string') {
    return type;
  }

  if (type.targetClass) {
    return `${type.type}<${type.targetClass}>`;
  }

  return `${type.type}`;
}; // Stores the entire schema of the app in a weird hybrid format somewhere between
// the mongo format and the Parse format. Soon, this will all be Parse format.


class SchemaController {
  constructor(databaseAdapter) {
    this._dbAdapter = databaseAdapter;
    this.schemaData = new SchemaData(_SchemaCache.default.all(), this.protectedFields);
    this.protectedFields = _Config.default.get(Parse.applicationId).protectedFields;

    const customIds = _Config.default.get(Parse.applicationId).allowCustomObjectId;

    const customIdRegEx = /^.{1,}$/u; // 1+ chars

    const autoIdRegEx = /^[a-zA-Z0-9]{1,}$/;
    this.userIdRegEx = customIds ? customIdRegEx : autoIdRegEx;

    this._dbAdapter.watch(() => {
      this.reloadData({
        clearCache: true
      });
    });
  }

  reloadData(options = {
    clearCache: false
  }) {
    if (this.reloadDataPromise && !options.clearCache) {
      return this.reloadDataPromise;
    }

    this.reloadDataPromise = this.getAllClasses(options).then(allSchemas => {
      this.schemaData = new SchemaData(allSchemas, this.protectedFields);
      delete this.reloadDataPromise;
    }, err => {
      this.schemaData = new SchemaData();
      delete this.reloadDataPromise;
      throw err;
    }).then(() => {});
    return this.reloadDataPromise;
  }

  getAllClasses(options = {
    clearCache: false
  }) {
    if (options.clearCache) {
      return this.setAllClasses();
    }

    const cached = _SchemaCache.default.all();

    if (cached && cached.length) {
      return Promise.resolve(cached);
    }

    return this.setAllClasses();
  }

  setAllClasses() {
    return this._dbAdapter.getAllClasses().then(allSchemas => allSchemas.map(injectDefaultSchema)).then(allSchemas => {
      _SchemaCache.default.put(allSchemas);

      return allSchemas;
    });
  }

  getOneSchema(className, allowVolatileClasses = false, options = {
    clearCache: false
  }) {
    if (options.clearCache) {
      _SchemaCache.default.clear();
    }

    if (allowVolatileClasses && volatileClasses.indexOf(className) > -1) {
      const data = this.schemaData[className];
      return Promise.resolve({
        className,
        fields: data.fields,
        classLevelPermissions: data.classLevelPermissions,
        indexes: data.indexes
      });
    }

    const cached = _SchemaCache.default.get(className);

    if (cached && !options.clearCache) {
      return Promise.resolve(cached);
    }

    return this.setAllClasses().then(allSchemas => {
      const oneSchema = allSchemas.find(schema => schema.className === className);

      if (!oneSchema) {
        return Promise.reject(undefined);
      }

      return oneSchema;
    });
  } // Create a new class that includes the three default fields.
  // ACL is an implicit column that does not get an entry in the
  // _SCHEMAS database. Returns a promise that resolves with the
  // created schema, in mongo format.
  // on success, and rejects with an error on fail. Ensure you
  // have authorization (master key, or client class creation
  // enabled) before calling this function.


  async addClassIfNotExists(className, fields = {}, classLevelPermissions, indexes = {}) {
    var validationError = this.validateNewClass(className, fields, classLevelPermissions);

    if (validationError) {
      if (validationError instanceof Parse.Error) {
        return Promise.reject(validationError);
      } else if (validationError.code && validationError.error) {
        return Promise.reject(new Parse.Error(validationError.code, validationError.error));
      }

      return Promise.reject(validationError);
    }

    try {
      const adapterSchema = await this._dbAdapter.createClass(className, convertSchemaToAdapterSchema({
        fields,
        classLevelPermissions,
        indexes,
        className
      })); // TODO: Remove by updating schema cache directly

      await this.reloadData({
        clearCache: true
      });
      const parseSchema = convertAdapterSchemaToParseSchema(adapterSchema);
      return parseSchema;
    } catch (error) {
      if (error && error.code === Parse.Error.DUPLICATE_VALUE) {
        throw new Parse.Error(Parse.Error.INVALID_CLASS_NAME, `Class ${className} already exists.`);
      } else {
        throw error;
      }
    }
  }

  updateClass(className, submittedFields, classLevelPermissions, indexes, database) {
    return this.getOneSchema(className).then(schema => {
      const existingFields = schema.fields;
      Object.keys(submittedFields).forEach(name => {
        const field = submittedFields[name];

        if (existingFields[name] && field.__op !== 'Delete') {
          throw new Parse.Error(255, `Field ${name} exists, cannot update.`);
        }

        if (!existingFields[name] && field.__op === 'Delete') {
          throw new Parse.Error(255, `Field ${name} does not exist, cannot delete.`);
        }
      });
      delete existingFields._rperm;
      delete existingFields._wperm;
      const newSchema = buildMergedSchemaObject(existingFields, submittedFields);
      const defaultFields = defaultColumns[className] || defaultColumns._Default;
      const fullNewSchema = Object.assign({}, newSchema, defaultFields);
      const validationError = this.validateSchemaData(className, newSchema, classLevelPermissions, Object.keys(existingFields));

      if (validationError) {
        throw new Parse.Error(validationError.code, validationError.error);
      } // Finally we have checked to make sure the request is valid and we can start deleting fields.
      // Do all deletions first, then a single save to _SCHEMA collection to handle all additions.


      const deletedFields = [];
      const insertedFields = [];
      Object.keys(submittedFields).forEach(fieldName => {
        if (submittedFields[fieldName].__op === 'Delete') {
          deletedFields.push(fieldName);
        } else {
          insertedFields.push(fieldName);
        }
      });
      let deletePromise = Promise.resolve();

      if (deletedFields.length > 0) {
        deletePromise = this.deleteFields(deletedFields, className, database);
      }

      let enforceFields = [];
      return deletePromise // Delete Everything
      .then(() => this.reloadData({
        clearCache: true
      })) // Reload our Schema, so we have all the new values
      .then(() => {
        const promises = insertedFields.map(fieldName => {
          const type = submittedFields[fieldName];
          return this.enforceFieldExists(className, fieldName, type);
        });
        return Promise.all(promises);
      }).then(results => {
        enforceFields = results.filter(result => !!result);
        return this.setPermissions(className, classLevelPermissions, newSchema);
      }).then(() => this._dbAdapter.setIndexesWithSchemaFormat(className, indexes, schema.indexes, fullNewSchema)).then(() => this.reloadData({
        clearCache: true
      })) //TODO: Move this logic into the database adapter
      .then(() => {
        this.ensureFields(enforceFields);
        const schema = this.schemaData[className];
        const reloadedSchema = {
          className: className,
          fields: schema.fields,
          classLevelPermissions: schema.classLevelPermissions
        };

        if (schema.indexes && Object.keys(schema.indexes).length !== 0) {
          reloadedSchema.indexes = schema.indexes;
        }

        return reloadedSchema;
      });
    }).catch(error => {
      if (error === undefined) {
        throw new Parse.Error(Parse.Error.INVALID_CLASS_NAME, `Class ${className} does not exist.`);
      } else {
        throw error;
      }
    });
  } // Returns a promise that resolves successfully to the new schema
  // object or fails with a reason.


  enforceClassExists(className) {
    if (this.schemaData[className]) {
      return Promise.resolve(this);
    } // We don't have this class. Update the schema


    return (// The schema update succeeded. Reload the schema
      this.addClassIfNotExists(className).catch(() => {
        // The schema update failed. This can be okay - it might
        // have failed because there's a race condition and a different
        // client is making the exact same schema update that we want.
        // So just reload the schema.
        return this.reloadData({
          clearCache: true
        });
      }).then(() => {
        // Ensure that the schema now validates
        if (this.schemaData[className]) {
          return this;
        } else {
          throw new Parse.Error(Parse.Error.INVALID_JSON, `Failed to add ${className}`);
        }
      }).catch(() => {
        // The schema still doesn't validate. Give up
        throw new Parse.Error(Parse.Error.INVALID_JSON, 'schema class name does not revalidate');
      })
    );
  }

  validateNewClass(className, fields = {}, classLevelPermissions) {
    if (this.schemaData[className]) {
      throw new Parse.Error(Parse.Error.INVALID_CLASS_NAME, `Class ${className} already exists.`);
    }

    if (!classNameIsValid(className)) {
      return {
        code: Parse.Error.INVALID_CLASS_NAME,
        error: invalidClassNameMessage(className)
      };
    }

    return this.validateSchemaData(className, fields, classLevelPermissions, []);
  }

  validateSchemaData(className, fields, classLevelPermissions, existingFieldNames) {
    for (const fieldName in fields) {
      if (existingFieldNames.indexOf(fieldName) < 0) {
        if (!fieldNameIsValid(fieldName, className)) {
          return {
            code: Parse.Error.INVALID_KEY_NAME,
            error: 'invalid field name: ' + fieldName
          };
        }

        if (!fieldNameIsValidForClass(fieldName, className)) {
          return {
            code: 136,
            error: 'field ' + fieldName + ' cannot be added'
          };
        }

        const fieldType = fields[fieldName];
        const error = fieldTypeIsInvalid(fieldType);
        if (error) return {
          code: error.code,
          error: error.message
        };

        if (fieldType.defaultValue !== undefined) {
          let defaultValueType = getType(fieldType.defaultValue);

          if (typeof defaultValueType === 'string') {
            defaultValueType = {
              type: defaultValueType
            };
          } else if (typeof defaultValueType === 'object' && fieldType.type === 'Relation') {
            return {
              code: Parse.Error.INCORRECT_TYPE,
              error: `The 'default value' option is not applicable for ${typeToString(fieldType)}`
            };
          }

          if (!dbTypeMatchesObjectType(fieldType, defaultValueType)) {
            return {
              code: Parse.Error.INCORRECT_TYPE,
              error: `schema mismatch for ${className}.${fieldName} default value; expected ${typeToString(fieldType)} but got ${typeToString(defaultValueType)}`
            };
          }
        } else if (fieldType.required) {
          if (typeof fieldType === 'object' && fieldType.type === 'Relation') {
            return {
              code: Parse.Error.INCORRECT_TYPE,
              error: `The 'required' option is not applicable for ${typeToString(fieldType)}`
            };
          }
        }
      }
    }

    for (const fieldName in defaultColumns[className]) {
      fields[fieldName] = defaultColumns[className][fieldName];
    }

    const geoPoints = Object.keys(fields).filter(key => fields[key] && fields[key].type === 'GeoPoint');

    if (geoPoints.length > 1) {
      return {
        code: Parse.Error.INCORRECT_TYPE,
        error: 'currently, only one GeoPoint field may exist in an object. Adding ' + geoPoints[1] + ' when ' + geoPoints[0] + ' already exists.'
      };
    }

    validateCLP(classLevelPermissions, fields, this.userIdRegEx);
  } // Sets the Class-level permissions for a given className, which must exist.


  async setPermissions(className, perms, newSchema) {
    if (typeof perms === 'undefined') {
      return Promise.resolve();
    }

    validateCLP(perms, newSchema, this.userIdRegEx);
    await this._dbAdapter.setClassLevelPermissions(className, perms);

    const cached = _SchemaCache.default.get(className);

    if (cached) {
      cached.classLevelPermissions = perms;
    }
  } // Returns a promise that resolves successfully to the new schema
  // object if the provided className-fieldName-type tuple is valid.
  // The className must already be validated.
  // If 'freeze' is true, refuse to update the schema for this field.


  enforceFieldExists(className, fieldName, type) {
    if (fieldName.indexOf('.') > 0) {
      // subdocument key (x.y) => ok if x is of type 'object'
      fieldName = fieldName.split('.')[0];
      type = 'Object';
    }

    if (!fieldNameIsValid(fieldName, className)) {
      throw new Parse.Error(Parse.Error.INVALID_KEY_NAME, `Invalid field name: ${fieldName}.`);
    } // If someone tries to create a new field with null/undefined as the value, return;


    if (!type) {
      return undefined;
    }

    const expectedType = this.getExpectedType(className, fieldName);

    if (typeof type === 'string') {
      type = {
        type
      };
    }

    if (type.defaultValue !== undefined) {
      let defaultValueType = getType(type.defaultValue);

      if (typeof defaultValueType === 'string') {
        defaultValueType = {
          type: defaultValueType
        };
      }

      if (!dbTypeMatchesObjectType(type, defaultValueType)) {
        throw new Parse.Error(Parse.Error.INCORRECT_TYPE, `schema mismatch for ${className}.${fieldName} default value; expected ${typeToString(type)} but got ${typeToString(defaultValueType)}`);
      }
    }

    if (expectedType) {
      if (!dbTypeMatchesObjectType(expectedType, type)) {
        throw new Parse.Error(Parse.Error.INCORRECT_TYPE, `schema mismatch for ${className}.${fieldName}; expected ${typeToString(expectedType)} but got ${typeToString(type)}`);
      }

      return undefined;
    }

    return this._dbAdapter.addFieldIfNotExists(className, fieldName, type).catch(error => {
      if (error.code == Parse.Error.INCORRECT_TYPE) {
        // Make sure that we throw errors when it is appropriate to do so.
        throw error;
      } // The update failed. This can be okay - it might have been a race
      // condition where another client updated the schema in the same
      // way that we wanted to. So, just reload the schema


      return Promise.resolve();
    }).then(() => {
      return {
        className,
        fieldName,
        type
      };
    });
  }

  ensureFields(fields) {
    for (let i = 0; i < fields.length; i += 1) {
      const {
        className,
        fieldName
      } = fields[i];
      let {
        type
      } = fields[i];
      const expectedType = this.getExpectedType(className, fieldName);

      if (typeof type === 'string') {
        type = {
          type: type
        };
      }

      if (!expectedType || !dbTypeMatchesObjectType(expectedType, type)) {
        throw new Parse.Error(Parse.Error.INVALID_JSON, `Could not add field ${fieldName}`);
      }
    }
  } // maintain compatibility


  deleteField(fieldName, className, database) {
    return this.deleteFields([fieldName], className, database);
  } // Delete fields, and remove that data from all objects. This is intended
  // to remove unused fields, if other writers are writing objects that include
  // this field, the field may reappear. Returns a Promise that resolves with
  // no object on success, or rejects with { code, error } on failure.
  // Passing the database and prefix is necessary in order to drop relation collections
  // and remove fields from objects. Ideally the database would belong to
  // a database adapter and this function would close over it or access it via member.


  deleteFields(fieldNames, className, database) {
    if (!classNameIsValid(className)) {
      throw new Parse.Error(Parse.Error.INVALID_CLASS_NAME, invalidClassNameMessage(className));
    }

    fieldNames.forEach(fieldName => {
      if (!fieldNameIsValid(fieldName, className)) {
        throw new Parse.Error(Parse.Error.INVALID_KEY_NAME, `invalid field name: ${fieldName}`);
      } //Don't allow deleting the default fields.


      if (!fieldNameIsValidForClass(fieldName, className)) {
        throw new Parse.Error(136, `field ${fieldName} cannot be changed`);
      }
    });
    return this.getOneSchema(className, false, {
      clearCache: true
    }).catch(error => {
      if (error === undefined) {
        throw new Parse.Error(Parse.Error.INVALID_CLASS_NAME, `Class ${className} does not exist.`);
      } else {
        throw error;
      }
    }).then(schema => {
      fieldNames.forEach(fieldName => {
        if (!schema.fields[fieldName]) {
          throw new Parse.Error(255, `Field ${fieldName} does not exist, cannot delete.`);
        }
      });

      const schemaFields = _objectSpread({}, schema.fields);

      return database.adapter.deleteFields(className, schema, fieldNames).then(() => {
        return Promise.all(fieldNames.map(fieldName => {
          const field = schemaFields[fieldName];

          if (field && field.type === 'Relation') {
            //For relations, drop the _Join table
            return database.adapter.deleteClass(`_Join:${fieldName}:${className}`);
          }

          return Promise.resolve();
        }));
      });
    }).then(() => {
      _SchemaCache.default.clear();
    });
  } // Validates an object provided in REST format.
  // Returns a promise that resolves to the new schema if this object is
  // valid.


  async validateObject(className, object, query) {
    let geocount = 0;
    const schema = await this.enforceClassExists(className);
    const promises = [];

    for (const fieldName in object) {
      if (object[fieldName] && getType(object[fieldName]) === 'GeoPoint') {
        geocount++;
      }

      if (geocount > 1) {
        return Promise.reject(new Parse.Error(Parse.Error.INCORRECT_TYPE, 'there can only be one geopoint field in a class'));
      }
    }

    for (const fieldName in object) {
      if (object[fieldName] === undefined) {
        continue;
      }

      const expected = getType(object[fieldName]);

      if (!expected) {
        continue;
      }

      if (fieldName === 'ACL') {
        // Every object has ACL implicitly.
        continue;
      }

      promises.push(schema.enforceFieldExists(className, fieldName, expected));
    }

    const results = await Promise.all(promises);
    const enforceFields = results.filter(result => !!result);

    if (enforceFields.length !== 0) {
      // TODO: Remove by updating schema cache directly
      await this.reloadData({
        clearCache: true
      });
    }

    this.ensureFields(enforceFields);
    const promise = Promise.resolve(schema);
    return thenValidateRequiredColumns(promise, className, object, query);
  } // Validates that all the properties are set for the object


  validateRequiredColumns(className, object, query) {
    const columns = requiredColumns[className];

    if (!columns || columns.length == 0) {
      return Promise.resolve(this);
    }

    const missingColumns = columns.filter(function (column) {
      if (query && query.objectId) {
        if (object[column] && typeof object[column] === 'object') {
          // Trying to delete a required column
          return object[column].__op == 'Delete';
        } // Not trying to do anything there


        return false;
      }

      return !object[column];
    });

    if (missingColumns.length > 0) {
      throw new Parse.Error(Parse.Error.INCORRECT_TYPE, missingColumns[0] + ' is required.');
    }

    return Promise.resolve(this);
  }

  testPermissionsForClassName(className, aclGroup, operation) {
    return SchemaController.testPermissions(this.getClassLevelPermissions(className), aclGroup, operation);
  } // Tests that the class level permission let pass the operation for a given aclGroup


  static testPermissions(classPermissions, aclGroup, operation) {
    if (!classPermissions || !classPermissions[operation]) {
      return true;
    }

    const perms = classPermissions[operation];

    if (perms['*']) {
      return true;
    } // Check permissions against the aclGroup provided (array of userId/roles)


    if (aclGroup.some(acl => {
      return perms[acl] === true;
    })) {
      return true;
    }

    return false;
  } // Validates an operation passes class-level-permissions set in the schema


  static validatePermission(classPermissions, className, aclGroup, operation, action) {
    if (SchemaController.testPermissions(classPermissions, aclGroup, operation)) {
      return Promise.resolve();
    }

    if (!classPermissions || !classPermissions[operation]) {
      return true;
    }

    const perms = classPermissions[operation]; // If only for authenticated users
    // make sure we have an aclGroup

    if (perms['requiresAuthentication']) {
      // If aclGroup has * (public)
      if (!aclGroup || aclGroup.length == 0) {
        throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Permission denied, user needs to be authenticated.');
      } else if (aclGroup.indexOf('*') > -1 && aclGroup.length == 1) {
        throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Permission denied, user needs to be authenticated.');
      } // requiresAuthentication passed, just move forward
      // probably would be wise at some point to rename to 'authenticatedUser'


      return Promise.resolve();
    } // No matching CLP, let's check the Pointer permissions
    // And handle those later


    const permissionField = ['get', 'find', 'count'].indexOf(operation) > -1 ? 'readUserFields' : 'writeUserFields'; // Reject create when write lockdown

    if (permissionField == 'writeUserFields' && operation == 'create') {
      throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, `Permission denied for action ${operation} on class ${className}.`);
    } // Process the readUserFields later


    if (Array.isArray(classPermissions[permissionField]) && classPermissions[permissionField].length > 0) {
      return Promise.resolve();
    }

    const pointerFields = classPermissions[operation].pointerFields;

    if (Array.isArray(pointerFields) && pointerFields.length > 0) {
      // any op except 'addField as part of create' is ok.
      if (operation !== 'addField' || action === 'update') {
        // We can allow adding field on update flow only.
        return Promise.resolve();
      }
    }

    throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, `Permission denied for action ${operation} on class ${className}.`);
  } // Validates an operation passes class-level-permissions set in the schema


  validatePermission(className, aclGroup, operation, action) {
    return SchemaController.validatePermission(this.getClassLevelPermissions(className), className, aclGroup, operation, action);
  }

  getClassLevelPermissions(className) {
    return this.schemaData[className] && this.schemaData[className].classLevelPermissions;
  } // Returns the expected type for a className+key combination
  // or undefined if the schema is not set


  getExpectedType(className, fieldName) {
    if (this.schemaData[className]) {
      const expectedType = this.schemaData[className].fields[fieldName];
      return expectedType === 'map' ? 'Object' : expectedType;
    }

    return undefined;
  } // Checks if a given class is in the schema.


  hasClass(className) {
    if (this.schemaData[className]) {
      return Promise.resolve(true);
    }

    return this.reloadData().then(() => !!this.schemaData[className]);
  }

} // Returns a promise for a new Schema.


exports.SchemaController = exports.default = SchemaController;

const load = (dbAdapter, options) => {
  const schema = new SchemaController(dbAdapter);
  return schema.reloadData(options).then(() => schema);
}; // Builds a new schema (in schema API response format) out of an
// existing mongo schema + a schemas API put request. This response
// does not include the default fields, as it is intended to be passed
// to mongoSchemaFromFieldsAndClassName. No validation is done here, it
// is done in mongoSchemaFromFieldsAndClassName.


exports.load = load;

function buildMergedSchemaObject(existingFields, putRequest) {
  const newSchema = {}; // -disable-next

  const sysSchemaField = Object.keys(defaultColumns).indexOf(existingFields._id) === -1 ? [] : Object.keys(defaultColumns[existingFields._id]);

  for (const oldField in existingFields) {
    if (oldField !== '_id' && oldField !== 'ACL' && oldField !== 'updatedAt' && oldField !== 'createdAt' && oldField !== 'objectId') {
      if (sysSchemaField.length > 0 && sysSchemaField.indexOf(oldField) !== -1) {
        continue;
      }

      const fieldIsDeleted = putRequest[oldField] && putRequest[oldField].__op === 'Delete';

      if (!fieldIsDeleted) {
        newSchema[oldField] = existingFields[oldField];
      }
    }
  }

  for (const newField in putRequest) {
    if (newField !== 'objectId' && putRequest[newField].__op !== 'Delete') {
      if (sysSchemaField.length > 0 && sysSchemaField.indexOf(newField) !== -1) {
        continue;
      }

      newSchema[newField] = putRequest[newField];
    }
  }

  return newSchema;
} // Given a schema promise, construct another schema promise that
// validates this field once the schema loads.


function thenValidateRequiredColumns(schemaPromise, className, object, query) {
  return schemaPromise.then(schema => {
    return schema.validateRequiredColumns(className, object, query);
  });
} // Gets the type from a REST API formatted object, where 'type' is
// extended past javascript types to include the rest of the Parse
// type system.
// The output should be a valid schema value.
// TODO: ensure that this is compatible with the format used in Open DB


function getType(obj) {
  const type = typeof obj;

  switch (type) {
    case 'boolean':
      return 'Boolean';

    case 'string':
      return 'String';

    case 'number':
      return 'Number';

    case 'map':
    case 'object':
      if (!obj) {
        return undefined;
      }

      return getObjectType(obj);

    case 'function':
    case 'symbol':
    case 'undefined':
    default:
      throw 'bad obj: ' + obj;
  }
} // This gets the type for non-JSON types like pointers and files, but
// also gets the appropriate type for $ operators.
// Returns null if the type is unknown.


function getObjectType(obj) {
  if (obj instanceof Array) {
    return 'Array';
  }

  if (obj.__type) {
    switch (obj.__type) {
      case 'Pointer':
        if (obj.className) {
          return {
            type: 'Pointer',
            targetClass: obj.className
          };
        }

        break;

      case 'Relation':
        if (obj.className) {
          return {
            type: 'Relation',
            targetClass: obj.className
          };
        }

        break;

      case 'File':
        if (obj.name) {
          return 'File';
        }

        break;

      case 'Date':
        if (obj.iso) {
          return 'Date';
        }

        break;

      case 'GeoPoint':
        if (obj.latitude != null && obj.longitude != null) {
          return 'GeoPoint';
        }

        break;

      case 'Bytes':
        if (obj.base64) {
          return 'Bytes';
        }

        break;

      case 'Polygon':
        if (obj.coordinates) {
          return 'Polygon';
        }

        break;
    }

    throw new Parse.Error(Parse.Error.INCORRECT_TYPE, 'This is not a valid ' + obj.__type);
  }

  if (obj['$ne']) {
    return getObjectType(obj['$ne']);
  }

  if (obj.__op) {
    switch (obj.__op) {
      case 'Increment':
        return 'Number';

      case 'Delete':
        return null;

      case 'Add':
      case 'AddUnique':
      case 'Remove':
        return 'Array';

      case 'AddRelation':
      case 'RemoveRelation':
        return {
          type: 'Relation',
          targetClass: obj.objects[0].className
        };

      case 'Batch':
        return getObjectType(obj.ops[0]);

      default:
        throw 'unexpected op: ' + obj.__op;
    }
  }

  return 'Object';
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9Db250cm9sbGVycy9TY2hlbWFDb250cm9sbGVyLmpzIl0sIm5hbWVzIjpbIlBhcnNlIiwicmVxdWlyZSIsImRlZmF1bHRDb2x1bW5zIiwiT2JqZWN0IiwiZnJlZXplIiwiX0RlZmF1bHQiLCJvYmplY3RJZCIsInR5cGUiLCJjcmVhdGVkQXQiLCJ1cGRhdGVkQXQiLCJBQ0wiLCJfVXNlciIsInVzZXJuYW1lIiwicGFzc3dvcmQiLCJlbWFpbCIsImVtYWlsVmVyaWZpZWQiLCJhdXRoRGF0YSIsIl9JbnN0YWxsYXRpb24iLCJpbnN0YWxsYXRpb25JZCIsImRldmljZVRva2VuIiwiY2hhbm5lbHMiLCJkZXZpY2VUeXBlIiwicHVzaFR5cGUiLCJHQ01TZW5kZXJJZCIsInRpbWVab25lIiwibG9jYWxlSWRlbnRpZmllciIsImJhZGdlIiwiYXBwVmVyc2lvbiIsImFwcE5hbWUiLCJhcHBJZGVudGlmaWVyIiwicGFyc2VWZXJzaW9uIiwiX1JvbGUiLCJuYW1lIiwidXNlcnMiLCJ0YXJnZXRDbGFzcyIsInJvbGVzIiwiX1Nlc3Npb24iLCJyZXN0cmljdGVkIiwidXNlciIsInNlc3Npb25Ub2tlbiIsImV4cGlyZXNBdCIsImNyZWF0ZWRXaXRoIiwiX1Byb2R1Y3QiLCJwcm9kdWN0SWRlbnRpZmllciIsImRvd25sb2FkIiwiZG93bmxvYWROYW1lIiwiaWNvbiIsIm9yZGVyIiwidGl0bGUiLCJzdWJ0aXRsZSIsIl9QdXNoU3RhdHVzIiwicHVzaFRpbWUiLCJzb3VyY2UiLCJxdWVyeSIsInBheWxvYWQiLCJleHBpcnkiLCJleHBpcmF0aW9uX2ludGVydmFsIiwic3RhdHVzIiwibnVtU2VudCIsIm51bUZhaWxlZCIsInB1c2hIYXNoIiwiZXJyb3JNZXNzYWdlIiwic2VudFBlclR5cGUiLCJmYWlsZWRQZXJUeXBlIiwic2VudFBlclVUQ09mZnNldCIsImZhaWxlZFBlclVUQ09mZnNldCIsImNvdW50IiwiX0pvYlN0YXR1cyIsImpvYk5hbWUiLCJtZXNzYWdlIiwicGFyYW1zIiwiZmluaXNoZWRBdCIsIl9Kb2JTY2hlZHVsZSIsImRlc2NyaXB0aW9uIiwic3RhcnRBZnRlciIsImRheXNPZldlZWsiLCJ0aW1lT2ZEYXkiLCJsYXN0UnVuIiwicmVwZWF0TWludXRlcyIsIl9Ib29rcyIsImZ1bmN0aW9uTmFtZSIsImNsYXNzTmFtZSIsInRyaWdnZXJOYW1lIiwidXJsIiwiX0dsb2JhbENvbmZpZyIsIm1hc3RlcktleU9ubHkiLCJfR3JhcGhRTENvbmZpZyIsImNvbmZpZyIsIl9BdWRpZW5jZSIsImxhc3RVc2VkIiwidGltZXNVc2VkIiwiX0lkZW1wb3RlbmN5IiwicmVxSWQiLCJleHBpcmUiLCJyZXF1aXJlZENvbHVtbnMiLCJpbnZhbGlkQ29sdW1ucyIsInN5c3RlbUNsYXNzZXMiLCJ2b2xhdGlsZUNsYXNzZXMiLCJyb2xlUmVnZXgiLCJwcm90ZWN0ZWRGaWVsZHNQb2ludGVyUmVnZXgiLCJwdWJsaWNSZWdleCIsImF1dGhlbnRpY2F0ZWRSZWdleCIsInJlcXVpcmVzQXV0aGVudGljYXRpb25SZWdleCIsImNscFBvaW50ZXJSZWdleCIsInByb3RlY3RlZEZpZWxkc1JlZ2V4IiwiY2xwRmllbGRzUmVnZXgiLCJ2YWxpZGF0ZVBlcm1pc3Npb25LZXkiLCJrZXkiLCJ1c2VySWRSZWdFeHAiLCJtYXRjaGVzU29tZSIsInJlZ0V4IiwibWF0Y2giLCJ2YWxpZCIsIkVycm9yIiwiSU5WQUxJRF9KU09OIiwidmFsaWRhdGVQcm90ZWN0ZWRGaWVsZHNLZXkiLCJDTFBWYWxpZEtleXMiLCJ2YWxpZGF0ZUNMUCIsInBlcm1zIiwiZmllbGRzIiwib3BlcmF0aW9uS2V5IiwiaW5kZXhPZiIsIm9wZXJhdGlvbiIsInZhbGlkYXRlQ0xQanNvbiIsImZpZWxkTmFtZSIsInZhbGlkYXRlUG9pbnRlclBlcm1pc3Npb24iLCJlbnRpdHkiLCJwcm90ZWN0ZWRGaWVsZHMiLCJBcnJheSIsImlzQXJyYXkiLCJmaWVsZCIsInByb3RvdHlwZSIsImhhc093blByb3BlcnR5IiwiY2FsbCIsInBvaW50ZXJGaWVsZHMiLCJwb2ludGVyRmllbGQiLCJwZXJtaXQiLCJqb2luQ2xhc3NSZWdleCIsImNsYXNzQW5kRmllbGRSZWdleCIsImNsYXNzTmFtZUlzVmFsaWQiLCJ0ZXN0IiwiZmllbGROYW1lSXNWYWxpZCIsImluY2x1ZGVzIiwiZmllbGROYW1lSXNWYWxpZEZvckNsYXNzIiwiaW52YWxpZENsYXNzTmFtZU1lc3NhZ2UiLCJpbnZhbGlkSnNvbkVycm9yIiwidmFsaWROb25SZWxhdGlvbk9yUG9pbnRlclR5cGVzIiwiZmllbGRUeXBlSXNJbnZhbGlkIiwiSU5WQUxJRF9DTEFTU19OQU1FIiwidW5kZWZpbmVkIiwiSU5DT1JSRUNUX1RZUEUiLCJjb252ZXJ0U2NoZW1hVG9BZGFwdGVyU2NoZW1hIiwic2NoZW1hIiwiaW5qZWN0RGVmYXVsdFNjaGVtYSIsIl9ycGVybSIsIl93cGVybSIsIl9oYXNoZWRfcGFzc3dvcmQiLCJjb252ZXJ0QWRhcHRlclNjaGVtYVRvUGFyc2VTY2hlbWEiLCJpbmRleGVzIiwia2V5cyIsImxlbmd0aCIsIlNjaGVtYURhdGEiLCJjb25zdHJ1Y3RvciIsImFsbFNjaGVtYXMiLCJfX2RhdGEiLCJfX3Byb3RlY3RlZEZpZWxkcyIsImZvckVhY2giLCJkZWZpbmVQcm9wZXJ0eSIsImdldCIsImRhdGEiLCJjbGFzc0xldmVsUGVybWlzc2lvbnMiLCJjbGFzc1Byb3RlY3RlZEZpZWxkcyIsInVucSIsIlNldCIsImZyb20iLCJkZWZhdWx0U2NoZW1hIiwiX0hvb2tzU2NoZW1hIiwiX0dsb2JhbENvbmZpZ1NjaGVtYSIsIl9HcmFwaFFMQ29uZmlnU2NoZW1hIiwiX1B1c2hTdGF0dXNTY2hlbWEiLCJfSm9iU3RhdHVzU2NoZW1hIiwiX0pvYlNjaGVkdWxlU2NoZW1hIiwiX0F1ZGllbmNlU2NoZW1hIiwiX0lkZW1wb3RlbmN5U2NoZW1hIiwiVm9sYXRpbGVDbGFzc2VzU2NoZW1hcyIsImRiVHlwZU1hdGNoZXNPYmplY3RUeXBlIiwiZGJUeXBlIiwib2JqZWN0VHlwZSIsInR5cGVUb1N0cmluZyIsIlNjaGVtYUNvbnRyb2xsZXIiLCJkYXRhYmFzZUFkYXB0ZXIiLCJfZGJBZGFwdGVyIiwic2NoZW1hRGF0YSIsIlNjaGVtYUNhY2hlIiwiYWxsIiwiQ29uZmlnIiwiYXBwbGljYXRpb25JZCIsImN1c3RvbUlkcyIsImFsbG93Q3VzdG9tT2JqZWN0SWQiLCJjdXN0b21JZFJlZ0V4IiwiYXV0b0lkUmVnRXgiLCJ1c2VySWRSZWdFeCIsIndhdGNoIiwicmVsb2FkRGF0YSIsImNsZWFyQ2FjaGUiLCJvcHRpb25zIiwicmVsb2FkRGF0YVByb21pc2UiLCJnZXRBbGxDbGFzc2VzIiwidGhlbiIsImVyciIsInNldEFsbENsYXNzZXMiLCJjYWNoZWQiLCJQcm9taXNlIiwicmVzb2x2ZSIsIm1hcCIsInB1dCIsImdldE9uZVNjaGVtYSIsImFsbG93Vm9sYXRpbGVDbGFzc2VzIiwiY2xlYXIiLCJvbmVTY2hlbWEiLCJmaW5kIiwicmVqZWN0IiwiYWRkQ2xhc3NJZk5vdEV4aXN0cyIsInZhbGlkYXRpb25FcnJvciIsInZhbGlkYXRlTmV3Q2xhc3MiLCJjb2RlIiwiZXJyb3IiLCJhZGFwdGVyU2NoZW1hIiwiY3JlYXRlQ2xhc3MiLCJwYXJzZVNjaGVtYSIsIkRVUExJQ0FURV9WQUxVRSIsInVwZGF0ZUNsYXNzIiwic3VibWl0dGVkRmllbGRzIiwiZGF0YWJhc2UiLCJleGlzdGluZ0ZpZWxkcyIsIl9fb3AiLCJuZXdTY2hlbWEiLCJidWlsZE1lcmdlZFNjaGVtYU9iamVjdCIsImRlZmF1bHRGaWVsZHMiLCJmdWxsTmV3U2NoZW1hIiwiYXNzaWduIiwidmFsaWRhdGVTY2hlbWFEYXRhIiwiZGVsZXRlZEZpZWxkcyIsImluc2VydGVkRmllbGRzIiwicHVzaCIsImRlbGV0ZVByb21pc2UiLCJkZWxldGVGaWVsZHMiLCJlbmZvcmNlRmllbGRzIiwicHJvbWlzZXMiLCJlbmZvcmNlRmllbGRFeGlzdHMiLCJyZXN1bHRzIiwiZmlsdGVyIiwicmVzdWx0Iiwic2V0UGVybWlzc2lvbnMiLCJzZXRJbmRleGVzV2l0aFNjaGVtYUZvcm1hdCIsImVuc3VyZUZpZWxkcyIsInJlbG9hZGVkU2NoZW1hIiwiY2F0Y2giLCJlbmZvcmNlQ2xhc3NFeGlzdHMiLCJleGlzdGluZ0ZpZWxkTmFtZXMiLCJJTlZBTElEX0tFWV9OQU1FIiwiZmllbGRUeXBlIiwiZGVmYXVsdFZhbHVlIiwiZGVmYXVsdFZhbHVlVHlwZSIsImdldFR5cGUiLCJyZXF1aXJlZCIsImdlb1BvaW50cyIsInNldENsYXNzTGV2ZWxQZXJtaXNzaW9ucyIsInNwbGl0IiwiZXhwZWN0ZWRUeXBlIiwiZ2V0RXhwZWN0ZWRUeXBlIiwiYWRkRmllbGRJZk5vdEV4aXN0cyIsImkiLCJkZWxldGVGaWVsZCIsImZpZWxkTmFtZXMiLCJzY2hlbWFGaWVsZHMiLCJhZGFwdGVyIiwiZGVsZXRlQ2xhc3MiLCJ2YWxpZGF0ZU9iamVjdCIsIm9iamVjdCIsImdlb2NvdW50IiwiZXhwZWN0ZWQiLCJwcm9taXNlIiwidGhlblZhbGlkYXRlUmVxdWlyZWRDb2x1bW5zIiwidmFsaWRhdGVSZXF1aXJlZENvbHVtbnMiLCJjb2x1bW5zIiwibWlzc2luZ0NvbHVtbnMiLCJjb2x1bW4iLCJ0ZXN0UGVybWlzc2lvbnNGb3JDbGFzc05hbWUiLCJhY2xHcm91cCIsInRlc3RQZXJtaXNzaW9ucyIsImdldENsYXNzTGV2ZWxQZXJtaXNzaW9ucyIsImNsYXNzUGVybWlzc2lvbnMiLCJzb21lIiwiYWNsIiwidmFsaWRhdGVQZXJtaXNzaW9uIiwiYWN0aW9uIiwiT0JKRUNUX05PVF9GT1VORCIsInBlcm1pc3Npb25GaWVsZCIsIk9QRVJBVElPTl9GT1JCSURERU4iLCJoYXNDbGFzcyIsImxvYWQiLCJkYkFkYXB0ZXIiLCJwdXRSZXF1ZXN0Iiwic3lzU2NoZW1hRmllbGQiLCJfaWQiLCJvbGRGaWVsZCIsImZpZWxkSXNEZWxldGVkIiwibmV3RmllbGQiLCJzY2hlbWFQcm9taXNlIiwib2JqIiwiZ2V0T2JqZWN0VHlwZSIsIl9fdHlwZSIsImlzbyIsImxhdGl0dWRlIiwibG9uZ2l0dWRlIiwiYmFzZTY0Iiwi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RCxHQUFHLENBQUNTLEdBQUosQ0FBUSxDQUFSLENBQUQsQ0FBcEI7O0FBQ0Y7QUFDRSxjQUFNLG9CQUFvQlQsR0FBRyxDQUFDM0UsSUFBOUI7QUFsQko7QUFvQkQ7O0FBQ0QsU0FBTyxRQUFQO0FBQ0QiLCJzb3VyY2VzQ29udGVudCI6WyIvLyBAZmxvd1xuLy8gVGhpcyBjbGFzcyBoYW5kbGVzIHNjaGVtYSB2YWxpZGF0aW9uLCBwZXJzaXN0ZW5jZSwgYW5kIG1vZGlmaWNhdGlvbi5cbi8vXG4vLyBFYWNoIGluZGl2aWR1YWwgU2NoZW1hIG9iamVjdCBzaG91bGQgYmUgaW1tdXRhYmxlLiBUaGUgaGVscGVycyB0b1xuLy8gZG8gdGhpbmdzIHdpdGggdGhlIFNjaGVtYSBqdXN0IHJldHVybiBhIG5ldyBzY2hlbWEgd2hlbiB0aGUgc2NoZW1hXG4vLyBpcyBjaGFuZ2VkLlxuLy9cbi8vIFRoZSBjYW5vbmljYWwgcGxhY2UgdG8gc3RvcmUgdGhpcyBTY2hlbWEgaXMgaW4gdGhlIGRhdGFiYXNlIGl0c2VsZixcbi8vIGluIGEgX1NDSEVNQSBjb2xsZWN0aW9uLiBUaGlzIGlzIG5vdCB0aGUgcmlnaHQgd2F5IHRvIGRvIGl0IGZvciBhblxuLy8gb3BlbiBzb3VyY2UgZnJhbWV3b3JrLCBidXQgaXQncyBiYWNrd2FyZCBjb21wYXRpYmxlLCBzbyB3ZSdyZVxuLy8ga2VlcGluZyBpdCB0aGlzIHdheSBmb3Igbm93LlxuLy9cbi8vIEluIEFQSS1oYW5kbGluZyBjb2RlLCB5b3Ugc2hvdWxkIG9ubHkgdXNlIHRoZSBTY2hlbWEgY2xhc3MgdmlhIHRoZVxuLy8gRGF0YWJhc2VDb250cm9sbGVyLiBUaGlzIHdpbGwgbGV0IHVzIHJlcGxhY2UgdGhlIHNjaGVtYSBsb2dpYyBmb3Jcbi8vIGRpZmZlcmVudCBkYXRhYmFzZXMuXG4vLyBUT0RPOiBoaWRlIGFsbCBzY2hlbWEgbG9naWMgaW5zaWRlIHRoZSBkYXRhYmFzZSBhZGFwdGVyLlxuLy8gQGZsb3ctZGlzYWJsZS1uZXh0XG5jb25zdCBQYXJzZSA9IHJlcXVpcmUoJ3BhcnNlL25vZGUnKS5QYXJzZTtcbmltcG9ydCB7IFN0b3JhZ2VBZGFwdGVyIH0gZnJvbSAnLi4vQWRhcHRlcnMvU3RvcmFnZS9TdG9yYWdlQWRhcHRlcic7XG5pbXBvcnQgU2NoZW1hQ2FjaGUgZnJvbSAnLi4vQWRhcHRlcnMvQ2FjaGUvU2NoZW1hQ2FjaGUnO1xuaW1wb3J0IERhdGFiYXNlQ29udHJvbGxlciBmcm9tICcuL0RhdGFiYXNlQ29udHJvbGxlcic7XG5pbXBvcnQgQ29uZmlnIGZyb20gJy4uL0NvbmZpZyc7XG4vLyBAZmxvdy1kaXNhYmxlLW5leHRcbmltcG9ydCBkZWVwY29weSBmcm9tICdkZWVwY29weSc7XG5pbXBvcnQgdHlwZSB7XG4gIFNjaGVtYSxcbiAgU2NoZW1hRmllbGRzLFxuICBDbGFzc0xldmVsUGVybWlzc2lvbnMsXG4gIFNjaGVtYUZpZWxkLFxuICBMb2FkU2NoZW1hT3B0aW9ucyxcbn0gZnJvbSAnLi90eXBlcyc7XG5cbmNvbnN0IGRlZmF1bHRDb2x1bW5zOiB7IFtzdHJpbmddOiBTY2hlbWFGaWVsZHMgfSA9IE9iamVjdC5mcmVlemUoe1xuICAvLyBDb250YWluIHRoZSBkZWZhdWx0IGNvbHVtbnMgZm9yIGV2ZXJ5IHBhcnNlIG9iamVjdCB0eXBlIChleGNlcHQgX0pvaW4gY29sbGVjdGlvbilcbiAgX0RlZmF1bHQ6IHtcbiAgICBvYmplY3RJZDogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICAgIGNyZWF0ZWRBdDogeyB0eXBlOiAnRGF0ZScgfSxcbiAgICB1cGRhdGVkQXQ6IHsgdHlwZTogJ0RhdGUnIH0sXG4gICAgQUNMOiB7IHR5cGU6ICdBQ0wnIH0sXG4gIH0sXG4gIC8vIFRoZSBhZGRpdGlvbmFsIGRlZmF1bHQgY29sdW1ucyBmb3IgdGhlIF9Vc2VyIGNvbGxlY3Rpb24gKGluIGFkZGl0aW9uIHRvIERlZmF1bHRDb2xzKVxuICBfVXNlcjoge1xuICAgIHVzZXJuYW1lOiB7IHR5cGU6ICdTdHJpbmcnIH0sXG4gICAgcGFzc3dvcmQ6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBlbWFpbDogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICAgIGVtYWlsVmVyaWZpZWQ6IHsgdHlwZTogJ0Jvb2xlYW4nIH0sXG4gICAgYXV0aERhdGE6IHsgdHlwZTogJ09iamVjdCcgfSxcbiAgfSxcbiAgLy8gVGhlIGFkZGl0aW9uYWwgZGVmYXVsdCBjb2x1bW5zIGZvciB0aGUgX0luc3RhbGxhdGlvbiBjb2xsZWN0aW9uIChpbiBhZGRpdGlvbiB0byBEZWZhdWx0Q29scylcbiAgX0luc3RhbGxhdGlvbjoge1xuICAgIGluc3RhbGxhdGlvbklkOiB7IHR5cGU6ICdTdHJpbmcnIH0sXG4gICAgZGV2aWNlVG9rZW46IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBjaGFubmVsczogeyB0eXBlOiAnQXJyYXknIH0sXG4gICAgZGV2aWNlVHlwZTogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICAgIHB1c2hUeXBlOiB7IHR5cGU6ICdTdHJpbmcnIH0sXG4gICAgR0NNU2VuZGVySWQ6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICB0aW1lWm9uZTogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICAgIGxvY2FsZUlkZW50aWZpZXI6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBiYWRnZTogeyB0eXBlOiAnTnVtYmVyJyB9LFxuICAgIGFwcFZlcnNpb246IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBhcHBOYW1lOiB7IHR5cGU6ICdTdHJpbmcnIH0sXG4gICAgYXBwSWRlbnRpZmllcjogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICAgIHBhcnNlVmVyc2lvbjogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICB9LFxuICAvLyBUaGUgYWRkaXRpb25hbCBkZWZhdWx0IGNvbHVtbnMgZm9yIHRoZSBfUm9sZSBjb2xsZWN0aW9uIChpbiBhZGRpdGlvbiB0byBEZWZhdWx0Q29scylcbiAgX1JvbGU6IHtcbiAgICBuYW1lOiB7IHR5cGU6ICdTdHJpbmcnIH0sXG4gICAgdXNlcnM6IHsgdHlwZTogJ1JlbGF0aW9uJywgdGFyZ2V0Q2xhc3M6ICdfVXNlcicgfSxcbiAgICByb2xlczogeyB0eXBlOiAnUmVsYXRpb24nLCB0YXJnZXRDbGFzczogJ19Sb2xlJyB9LFxuICB9LFxuICAvLyBUaGUgYWRkaXRpb25hbCBkZWZhdWx0IGNvbHVtbnMgZm9yIHRoZSBfU2Vzc2lvbiBjb2xsZWN0aW9uIChpbiBhZGRpdGlvbiB0byBEZWZhdWx0Q29scylcbiAgX1Nlc3Npb246IHtcbiAgICByZXN0cmljdGVkOiB7IHR5cGU6ICdCb29sZWFuJyB9LFxuICAgIHVzZXI6IHsgdHlwZTogJ1BvaW50ZXInLCB0YXJnZXRDbGFzczogJ19Vc2VyJyB9LFxuICAgIGluc3RhbGxhdGlvbklkOiB7IHR5cGU6ICdTdHJpbmcnIH0sXG4gICAgc2Vzc2lvblRva2VuOiB7IHR5cGU6ICdTdHJpbmcnIH0sXG4gICAgZXhwaXJlc0F0OiB7IHR5cGU6ICdEYXRlJyB9LFxuICAgIGNyZWF0ZWRXaXRoOiB7IHR5cGU6ICdPYmplY3QnIH0sXG4gIH0sXG4gIF9Qcm9kdWN0OiB7XG4gICAgcHJvZHVjdElkZW50aWZpZXI6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBkb3dubG9hZDogeyB0eXBlOiAnRmlsZScgfSxcbiAgICBkb3dubG9hZE5hbWU6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBpY29uOiB7IHR5cGU6ICdGaWxlJyB9LFxuICAgIG9yZGVyOiB7IHR5cGU6ICdOdW1iZXInIH0sXG4gICAgdGl0bGU6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBzdWJ0aXRsZTogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICB9LFxuICBfUHVzaFN0YXR1czoge1xuICAgIHB1c2hUaW1lOiB7IHR5cGU6ICdTdHJpbmcnIH0sXG4gICAgc291cmNlOiB7IHR5cGU6ICdTdHJpbmcnIH0sIC8vIHJlc3Qgb3Igd2VidWlcbiAgICBxdWVyeTogeyB0eXBlOiAnU3RyaW5nJyB9LCAvLyB0aGUgc3RyaW5naWZpZWQgSlNPTiBxdWVyeVxuICAgIHBheWxvYWQ6IHsgdHlwZTogJ1N0cmluZycgfSwgLy8gdGhlIHN0cmluZ2lmaWVkIEpTT04gcGF5bG9hZCxcbiAgICB0aXRsZTogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICAgIGV4cGlyeTogeyB0eXBlOiAnTnVtYmVyJyB9LFxuICAgIGV4cGlyYXRpb25faW50ZXJ2YWw6IHsgdHlwZTogJ051bWJlcicgfSxcbiAgICBzdGF0dXM6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBudW1TZW50OiB7IHR5cGU6ICdOdW1iZXInIH0sXG4gICAgbnVtRmFpbGVkOiB7IHR5cGU6ICdOdW1iZXInIH0sXG4gICAgcHVzaEhhc2g6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBlcnJvck1lc3NhZ2U6IHsgdHlwZTogJ09iamVjdCcgfSxcbiAgICBzZW50UGVyVHlwZTogeyB0eXBlOiAnT2JqZWN0JyB9LFxuICAgIGZhaWxlZFBlclR5cGU6IHsgdHlwZTogJ09iamVjdCcgfSxcbiAgICBzZW50UGVyVVRDT2Zmc2V0OiB7IHR5cGU6ICdPYmplY3QnIH0sXG4gICAgZmFpbGVkUGVyVVRDT2Zmc2V0OiB7IHR5cGU6ICdPYmplY3QnIH0sXG4gICAgY291bnQ6IHsgdHlwZTogJ051bWJlcicgfSwgLy8gdHJhY2tzICMgb2YgYmF0Y2hlcyBxdWV1ZWQgYW5kIHBlbmRpbmdcbiAgfSxcbiAgX0pvYlN0YXR1czoge1xuICAgIGpvYk5hbWU6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBzb3VyY2U6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBzdGF0dXM6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBtZXNzYWdlOiB7IHR5cGU6ICdTdHJpbmcnIH0sXG4gICAgcGFyYW1zOiB7IHR5cGU6ICdPYmplY3QnIH0sIC8vIHBhcmFtcyByZWNlaXZlZCB3aGVuIGNhbGxpbmcgdGhlIGpvYlxuICAgIGZpbmlzaGVkQXQ6IHsgdHlwZTogJ0RhdGUnIH0sXG4gIH0sXG4gIF9Kb2JTY2hlZHVsZToge1xuICAgIGpvYk5hbWU6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBkZXNjcmlwdGlvbjogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICAgIHBhcmFtczogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICAgIHN0YXJ0QWZ0ZXI6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBkYXlzT2ZXZWVrOiB7IHR5cGU6ICdBcnJheScgfSxcbiAgICB0aW1lT2ZEYXk6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBsYXN0UnVuOiB7IHR5cGU6ICdOdW1iZXInIH0sXG4gICAgcmVwZWF0TWludXRlczogeyB0eXBlOiAnTnVtYmVyJyB9LFxuICB9LFxuICBfSG9va3M6IHtcbiAgICBmdW5jdGlvbk5hbWU6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBjbGFzc05hbWU6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICB0cmlnZ2VyTmFtZTogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICAgIHVybDogeyB0eXBlOiAnU3RyaW5nJyB9LFxuICB9LFxuICBfR2xvYmFsQ29uZmlnOiB7XG4gICAgb2JqZWN0SWQ6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBwYXJhbXM6IHsgdHlwZTogJ09iamVjdCcgfSxcbiAgICBtYXN0ZXJLZXlPbmx5OiB7IHR5cGU6ICdPYmplY3QnIH0sXG4gIH0sXG4gIF9HcmFwaFFMQ29uZmlnOiB7XG4gICAgb2JqZWN0SWQ6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBjb25maWc6IHsgdHlwZTogJ09iamVjdCcgfSxcbiAgfSxcbiAgX0F1ZGllbmNlOiB7XG4gICAgb2JqZWN0SWQ6IHsgdHlwZTogJ1N0cmluZycgfSxcbiAgICBuYW1lOiB7IHR5cGU6ICdTdHJpbmcnIH0sXG4gICAgcXVlcnk6IHsgdHlwZTogJ1N0cmluZycgfSwgLy9zdG9yaW5nIHF1ZXJ5IGFzIEpTT04gc3RyaW5nIHRvIHByZXZlbnQgXCJOZXN0ZWQga2V5cyBzaG91bGQgbm90IGNvbnRhaW4gdGhlICckJyBvciAnLicgY2hhcmFjdGVyc1wiIGVycm9yXG4gICAgbGFzdFVzZWQ6IHsgdHlwZTogJ0RhdGUnIH0sXG4gICAgdGltZXNVc2VkOiB7IHR5cGU6ICdOdW1iZXInIH0sXG4gIH0sXG4gIF9JZGVtcG90ZW5jeToge1xuICAgIHJlcUlkOiB7IHR5cGU6ICdTdHJpbmcnIH0sXG4gICAgZXhwaXJlOiB7IHR5cGU6ICdEYXRlJyB9LFxuICB9LFxufSk7XG5cbmNvbnN0IHJlcXVpcmVkQ29sdW1ucyA9IE9iamVjdC5mcmVlemUoe1xuICBfUHJvZHVjdDogWydwcm9kdWN0SWRlbnRpZmllcicsICdpY29uJywgJ29yZGVyJywgJ3RpdGxlJywgJ3N1YnRpdGxlJ10sXG4gIF9Sb2xlOiBbJ25hbWUnLCAnQUNMJ10sXG59KTtcblxuY29uc3QgaW52YWxpZENvbHVtbnMgPSBbJ2xlbmd0aCddO1xuXG5jb25zdCBzeXN0ZW1DbGFzc2VzID0gT2JqZWN0LmZyZWV6ZShbXG4gICdfVXNlcicsXG4gICdfSW5zdGFsbGF0aW9uJyxcbiAgJ19Sb2xlJyxcbiAgJ19TZXNzaW9uJyxcbiAgJ19Qcm9kdWN0JyxcbiAgJ19QdXNoU3RhdHVzJyxcbiAgJ19Kb2JTdGF0dXMnLFxuICAnX0pvYlNjaGVkdWxlJyxcbiAgJ19BdWRpZW5jZScsXG4gICdfSWRlbXBvdGVuY3knLFxuXSk7XG5cbmNvbnN0IHZvbGF0aWxlQ2xhc3NlcyA9IE9iamVjdC5mcmVlemUoW1xuICAnX0pvYlN0YXR1cycsXG4gICdfUHVzaFN0YXR1cycsXG4gICdfSG9va3MnLFxuICAnX0dsb2JhbENvbmZpZycsXG4gICdfR3JhcGhRTENvbmZpZycsXG4gICdfSm9iU2NoZWR1bGUnLFxuICAnX0F1ZGllbmNlJyxcbiAgJ19JZGVtcG90ZW5jeScsXG5dKTtcblxuLy8gQW55dGhpbmcgdGhhdCBzdGFydCB3aXRoIHJvbGVcbmNvbnN0IHJvbGVSZWdleCA9IC9ecm9sZTouKi87XG4vLyBBbnl0aGluZyB0aGF0IHN0YXJ0cyB3aXRoIHVzZXJGaWVsZCAoYWxsb3dlZCBmb3IgcHJvdGVjdGVkIGZpZWxkcyBvbmx5KVxuY29uc3QgcHJvdGVjdGVkRmllbGRzUG9pbnRlclJlZ2V4ID0gL151c2VyRmllbGQ6LiovO1xuLy8gKiBwZXJtaXNzaW9uXG5jb25zdCBwdWJsaWNSZWdleCA9IC9eXFwqJC87XG5cbmNvbnN0IGF1dGhlbnRpY2F0ZWRSZWdleCA9IC9eYXV0aGVudGljYXRlZCQvO1xuXG5jb25zdCByZXF1aXJlc0F1dGhlbnRpY2F0aW9uUmVnZXggPSAvXnJlcXVpcmVzQXV0aGVudGljYXRpb24kLztcblxuY29uc3QgY2xwUG9pbnRlclJlZ2V4ID0gL15wb2ludGVyRmllbGRzJC87XG5cbi8vIHJlZ2V4IGZvciB2YWxpZGF0aW5nIGVudGl0aWVzIGluIHByb3RlY3RlZEZpZWxkcyBvYmplY3RcbmNvbnN0IHByb3RlY3RlZEZpZWxkc1JlZ2V4ID0gT2JqZWN0LmZyZWV6ZShbXG4gIHByb3RlY3RlZEZpZWxkc1BvaW50ZXJSZWdleCxcbiAgcHVibGljUmVnZXgsXG4gIGF1dGhlbnRpY2F0ZWRSZWdleCxcbiAgcm9sZVJlZ2V4LFxuXSk7XG5cbi8vIGNscCByZWdleFxuY29uc3QgY2xwRmllbGRzUmVnZXggPSBPYmplY3QuZnJlZXplKFtcbiAgY2xwUG9pbnRlclJlZ2V4LFxuICBwdWJsaWNSZWdleCxcbiAgcmVxdWlyZXNBdXRoZW50aWNhdGlvblJlZ2V4LFxuICByb2xlUmVnZXgsXG5dKTtcblxuZnVuY3Rpb24gdmFsaWRhdGVQZXJtaXNzaW9uS2V5KGtleSwgdXNlcklkUmVnRXhwKSB7XG4gIGxldCBtYXRjaGVzU29tZSA9IGZhbHNlO1xuICBmb3IgKGNvbnN0IHJlZ0V4IG9mIGNscEZpZWxkc1JlZ2V4KSB7XG4gICAgaWYgKGtleS5tYXRjaChyZWdFeCkgIT09IG51bGwpIHtcbiAgICAgIG1hdGNoZXNTb21lID0gdHJ1ZTtcbiAgICAgIGJyZWFrO1xuICAgIH1cbiAgfVxuXG4gIC8vIHVzZXJJZCBkZXBlbmRzIG9uIHN0YXJ0dXAgb3B0aW9ucyBzbyBpdCdzIGR5bmFtaWNcbiAgY29uc3QgdmFsaWQgPSBtYXRjaGVzU29tZSB8fCBrZXkubWF0Y2godXNlcklkUmVnRXhwKSAhPT0gbnVsbDtcbiAgaWYgKCF2YWxpZCkge1xuICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgIGAnJHtrZXl9JyBpcyBub3QgYSB2YWxpZCBrZXkgZm9yIGNsYXNzIGxldmVsIHBlcm1pc3Npb25zYFxuICAgICk7XG4gIH1cbn1cblxuZnVuY3Rpb24gdmFsaWRhdGVQcm90ZWN0ZWRGaWVsZHNLZXkoa2V5LCB1c2VySWRSZWdFeHApIHtcbiAgbGV0IG1hdGNoZXNTb21lID0gZmFsc2U7XG4gIGZvciAoY29uc3QgcmVnRXggb2YgcHJvdGVjdGVkRmllbGRzUmVnZXgpIHtcbiAgICBpZiAoa2V5Lm1hdGNoKHJlZ0V4KSAhPT0gbnVsbCkge1xuICAgICAgbWF0Y2hlc1NvbWUgPSB0cnVlO1xuICAgICAgYnJlYWs7XG4gICAgfVxuICB9XG5cbiAgLy8gdXNlcklkIHJlZ2V4IGRlcGVuZHMgb24gbGF1bmNoIG9wdGlvbnMgc28gaXQncyBkeW5hbWljXG4gIGNvbnN0IHZhbGlkID0gbWF0Y2hlc1NvbWUgfHwga2V5Lm1hdGNoKHVzZXJJZFJlZ0V4cCkgIT09IG51bGw7XG4gIGlmICghdmFsaWQpIHtcbiAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sXG4gICAgICBgJyR7a2V5fScgaXMgbm90IGEgdmFsaWQga2V5IGZvciBjbGFzcyBsZXZlbCBwZXJtaXNzaW9uc2BcbiAgICApO1xuICB9XG59XG5cbmNvbnN0IENMUFZhbGlkS2V5cyA9IE9iamVjdC5mcmVlemUoW1xuICAnZmluZCcsXG4gICdjb3VudCcsXG4gICdnZXQnLFxuICAnY3JlYXRlJyxcbiAgJ3VwZGF0ZScsXG4gICdkZWxldGUnLFxuICAnYWRkRmllbGQnLFxuICAncmVhZFVzZXJGaWVsZHMnLFxuICAnd3JpdGVVc2VyRmllbGRzJyxcbiAgJ3Byb3RlY3RlZEZpZWxkcycsXG5dKTtcblxuLy8gdmFsaWRhdGlvbiBiZWZvcmUgc2V0dGluZyBjbGFzcy1sZXZlbCBwZXJtaXNzaW9ucyBvbiBjb2xsZWN0aW9uXG5mdW5jdGlvbiB2YWxpZGF0ZUNMUChwZXJtczogQ2xhc3NMZXZlbFBlcm1pc3Npb25zLCBmaWVsZHM6IFNjaGVtYUZpZWxkcywgdXNlcklkUmVnRXhwOiBSZWdFeHApIHtcbiAgaWYgKCFwZXJtcykge1xuICAgIHJldHVybjtcbiAgfVxuICBmb3IgKGNvbnN0IG9wZXJhdGlvbktleSBpbiBwZXJtcykge1xuICAgIGlmIChDTFBWYWxpZEtleXMuaW5kZXhPZihvcGVyYXRpb25LZXkpID09IC0xKSB7XG4gICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgYCR7b3BlcmF0aW9uS2V5fSBpcyBub3QgYSB2YWxpZCBvcGVyYXRpb24gZm9yIGNsYXNzIGxldmVsIHBlcm1pc3Npb25zYFxuICAgICAgKTtcbiAgICB9XG5cbiAgICBjb25zdCBvcGVyYXRpb24gPSBwZXJtc1tvcGVyYXRpb25LZXldO1xuICAgIC8vIHByb2NlZWQgd2l0aCBuZXh0IG9wZXJhdGlvbktleVxuXG4gICAgLy8gdGhyb3dzIHdoZW4gcm9vdCBmaWVsZHMgYXJlIG9mIHdyb25nIHR5cGVcbiAgICB2YWxpZGF0ZUNMUGpzb24ob3BlcmF0aW9uLCBvcGVyYXRpb25LZXkpO1xuXG4gICAgaWYgKG9wZXJhdGlvbktleSA9PT0gJ3JlYWRVc2VyRmllbGRzJyB8fCBvcGVyYXRpb25LZXkgPT09ICd3cml0ZVVzZXJGaWVsZHMnKSB7XG4gICAgICAvLyB2YWxpZGF0ZSBncm91cGVkIHBvaW50ZXIgcGVybWlzc2lvbnNcbiAgICAgIC8vIG11c3QgYmUgYW4gYXJyYXkgd2l0aCBmaWVsZCBuYW1lc1xuICAgICAgZm9yIChjb25zdCBmaWVsZE5hbWUgb2Ygb3BlcmF0aW9uKSB7XG4gICAgICAgIHZhbGlkYXRlUG9pbnRlclBlcm1pc3Npb24oZmllbGROYW1lLCBmaWVsZHMsIG9wZXJhdGlvbktleSk7XG4gICAgICB9XG4gICAgICAvLyByZWFkVXNlckZpZWxkcyBhbmQgd3JpdGVyVXNlckZpZWxkcyBkbyBub3QgaGF2ZSBuZXNkdGVkIGZpZWxkc1xuICAgICAgLy8gcHJvY2VlZCB3aXRoIG5leHQgb3BlcmF0aW9uS2V5XG4gICAgICBjb250aW51ZTtcbiAgICB9XG5cbiAgICAvLyB2YWxpZGF0ZSBwcm90ZWN0ZWQgZmllbGRzXG4gICAgaWYgKG9wZXJhdGlvbktleSA9PT0gJ3Byb3RlY3RlZEZpZWxkcycpIHtcbiAgICAgIGZvciAoY29uc3QgZW50aXR5IGluIG9wZXJhdGlvbikge1xuICAgICAgICAvLyB0aHJvd3Mgb24gdW5leHBlY3RlZCBrZXlcbiAgICAgICAgdmFsaWRhdGVQcm90ZWN0ZWRGaWVsZHNLZXkoZW50aXR5LCB1c2VySWRSZWdFeHApO1xuXG4gICAgICAgIGNvbnN0IHByb3RlY3RlZEZpZWxkcyA9IG9wZXJhdGlvbltlbnRpdHldO1xuXG4gICAgICAgIGlmICghQXJyYXkuaXNBcnJheShwcm90ZWN0ZWRGaWVsZHMpKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgYCcke3Byb3RlY3RlZEZpZWxkc30nIGlzIG5vdCBhIHZhbGlkIHZhbHVlIGZvciBwcm90ZWN0ZWRGaWVsZHNbJHtlbnRpdHl9XSAtIGV4cGVjdGVkIGFuIGFycmF5LmBcbiAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gaWYgdGhlIGZpZWxkIGlzIGluIGZvcm0gb2YgYXJyYXlcbiAgICAgICAgZm9yIChjb25zdCBmaWVsZCBvZiBwcm90ZWN0ZWRGaWVsZHMpIHtcbiAgICAgICAgICAvLyBkbyBub3QgYWxsb293IHRvIHByb3RlY3QgZGVmYXVsdCBmaWVsZHNcbiAgICAgICAgICBpZiAoZGVmYXVsdENvbHVtbnMuX0RlZmF1bHRbZmllbGRdKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgICAgICAgYERlZmF1bHQgZmllbGQgJyR7ZmllbGR9JyBjYW4gbm90IGJlIHByb3RlY3RlZGBcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuICAgICAgICAgIC8vIGZpZWxkIHNob3VsZCBleGlzdCBvbiBjb2xsZWN0aW9uXG4gICAgICAgICAgaWYgKCFPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwoZmllbGRzLCBmaWVsZCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgICBgRmllbGQgJyR7ZmllbGR9JyBpbiBwcm90ZWN0ZWRGaWVsZHM6JHtlbnRpdHl9IGRvZXMgbm90IGV4aXN0YFxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIC8vIHByb2NlZWQgd2l0aCBuZXh0IG9wZXJhdGlvbktleVxuICAgICAgY29udGludWU7XG4gICAgfVxuXG4gICAgLy8gdmFsaWRhdGUgb3RoZXIgZmllbGRzXG4gICAgLy8gRW50aXR5IGNhbiBiZTpcbiAgICAvLyBcIipcIiAtIFB1YmxpYyxcbiAgICAvLyBcInJlcXVpcmVzQXV0aGVudGljYXRpb25cIiAtIGF1dGhlbnRpY2F0ZWQgdXNlcnMsXG4gICAgLy8gXCJvYmplY3RJZFwiIC0gX1VzZXIgaWQsXG4gICAgLy8gXCJyb2xlOnJvbGVuYW1lXCIsXG4gICAgLy8gXCJwb2ludGVyRmllbGRzXCIgLSBhcnJheSBvZiBmaWVsZCBuYW1lcyBjb250YWluaW5nIHBvaW50ZXJzIHRvIHVzZXJzXG4gICAgZm9yIChjb25zdCBlbnRpdHkgaW4gb3BlcmF0aW9uKSB7XG4gICAgICAvLyB0aHJvd3Mgb24gdW5leHBlY3RlZCBrZXlcbiAgICAgIHZhbGlkYXRlUGVybWlzc2lvbktleShlbnRpdHksIHVzZXJJZFJlZ0V4cCk7XG5cbiAgICAgIC8vIGVudGl0eSBjYW4gYmUgZWl0aGVyOlxuICAgICAgLy8gXCJwb2ludGVyRmllbGRzXCI6IHN0cmluZ1tdXG4gICAgICBpZiAoZW50aXR5ID09PSAncG9pbnRlckZpZWxkcycpIHtcbiAgICAgICAgY29uc3QgcG9pbnRlckZpZWxkcyA9IG9wZXJhdGlvbltlbnRpdHldO1xuXG4gICAgICAgIGlmIChBcnJheS5pc0FycmF5KHBvaW50ZXJGaWVsZHMpKSB7XG4gICAgICAgICAgZm9yIChjb25zdCBwb2ludGVyRmllbGQgb2YgcG9pbnRlckZpZWxkcykge1xuICAgICAgICAgICAgdmFsaWRhdGVQb2ludGVyUGVybWlzc2lvbihwb2ludGVyRmllbGQsIGZpZWxkcywgb3BlcmF0aW9uKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgYCcke3BvaW50ZXJGaWVsZHN9JyBpcyBub3QgYSB2YWxpZCB2YWx1ZSBmb3IgJHtvcGVyYXRpb25LZXl9WyR7ZW50aXR5fV0gLSBleHBlY3RlZCBhbiBhcnJheS5gXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBwcm9jZWVkIHdpdGggbmV4dCBlbnRpdHkga2V5XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICAvLyBvciBbZW50aXR5XTogYm9vbGVhblxuICAgICAgY29uc3QgcGVybWl0ID0gb3BlcmF0aW9uW2VudGl0eV07XG5cbiAgICAgIGlmIChwZXJtaXQgIT09IHRydWUpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgICBgJyR7cGVybWl0fScgaXMgbm90IGEgdmFsaWQgdmFsdWUgZm9yIGNsYXNzIGxldmVsIHBlcm1pc3Npb25zICR7b3BlcmF0aW9uS2V5fToke2VudGl0eX06JHtwZXJtaXR9YFxuICAgICAgICApO1xuICAgICAgfVxuICAgIH1cbiAgfVxufVxuXG5mdW5jdGlvbiB2YWxpZGF0ZUNMUGpzb24ob3BlcmF0aW9uOiBhbnksIG9wZXJhdGlvbktleTogc3RyaW5nKSB7XG4gIGlmIChvcGVyYXRpb25LZXkgPT09ICdyZWFkVXNlckZpZWxkcycgfHwgb3BlcmF0aW9uS2V5ID09PSAnd3JpdGVVc2VyRmllbGRzJykge1xuICAgIGlmICghQXJyYXkuaXNBcnJheShvcGVyYXRpb24pKSB7XG4gICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgYCcke29wZXJhdGlvbn0nIGlzIG5vdCBhIHZhbGlkIHZhbHVlIGZvciBjbGFzcyBsZXZlbCBwZXJtaXNzaW9ucyAke29wZXJhdGlvbktleX0gLSBtdXN0IGJlIGFuIGFycmF5YFxuICAgICAgKTtcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgaWYgKHR5cGVvZiBvcGVyYXRpb24gPT09ICdvYmplY3QnICYmIG9wZXJhdGlvbiAhPT0gbnVsbCkge1xuICAgICAgLy8gb2sgdG8gcHJvY2VlZFxuICAgICAgcmV0dXJuO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgYCcke29wZXJhdGlvbn0nIGlzIG5vdCBhIHZhbGlkIHZhbHVlIGZvciBjbGFzcyBsZXZlbCBwZXJtaXNzaW9ucyAke29wZXJhdGlvbktleX0gLSBtdXN0IGJlIGFuIG9iamVjdGBcbiAgICAgICk7XG4gICAgfVxuICB9XG59XG5cbmZ1bmN0aW9uIHZhbGlkYXRlUG9pbnRlclBlcm1pc3Npb24oZmllbGROYW1lOiBzdHJpbmcsIGZpZWxkczogT2JqZWN0LCBvcGVyYXRpb246IHN0cmluZykge1xuICAvLyBVc2VzIGNvbGxlY3Rpb24gc2NoZW1hIHRvIGVuc3VyZSB0aGUgZmllbGQgaXMgb2YgdHlwZTpcbiAgLy8gLSBQb2ludGVyPF9Vc2VyPiAocG9pbnRlcnMpXG4gIC8vIC0gQXJyYXlcbiAgLy9cbiAgLy8gICAgSXQncyBub3QgcG9zc2libGUgdG8gZW5mb3JjZSB0eXBlIG9uIEFycmF5J3MgaXRlbXMgaW4gc2NoZW1hXG4gIC8vICBzbyB3ZSBhY2NlcHQgYW55IEFycmF5IGZpZWxkLCBhbmQgbGF0ZXIgd2hlbiBhcHBseWluZyBwZXJtaXNzaW9uc1xuICAvLyAgb25seSBpdGVtcyB0aGF0IGFyZSBwb2ludGVycyB0byBfVXNlciBhcmUgY29uc2lkZXJlZC5cbiAgaWYgKFxuICAgICEoXG4gICAgICBmaWVsZHNbZmllbGROYW1lXSAmJlxuICAgICAgKChmaWVsZHNbZmllbGROYW1lXS50eXBlID09ICdQb2ludGVyJyAmJiBmaWVsZHNbZmllbGROYW1lXS50YXJnZXRDbGFzcyA9PSAnX1VzZXInKSB8fFxuICAgICAgICBmaWVsZHNbZmllbGROYW1lXS50eXBlID09ICdBcnJheScpXG4gICAgKVxuICApIHtcbiAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sXG4gICAgICBgJyR7ZmllbGROYW1lfScgaXMgbm90IGEgdmFsaWQgY29sdW1uIGZvciBjbGFzcyBsZXZlbCBwb2ludGVyIHBlcm1pc3Npb25zICR7b3BlcmF0aW9ufWBcbiAgICApO1xuICB9XG59XG5cbmNvbnN0IGpvaW5DbGFzc1JlZ2V4ID0gL15fSm9pbjpbQS1aYS16MC05X10rOltBLVphLXowLTlfXSsvO1xuY29uc3QgY2xhc3NBbmRGaWVsZFJlZ2V4ID0gL15bQS1aYS16XVtBLVphLXowLTlfXSokLztcbmZ1bmN0aW9uIGNsYXNzTmFtZUlzVmFsaWQoY2xhc3NOYW1lOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgLy8gVmFsaWQgY2xhc3NlcyBtdXN0OlxuICByZXR1cm4gKFxuICAgIC8vIEJlIG9uZSBvZiBfVXNlciwgX0luc3RhbGxhdGlvbiwgX1JvbGUsIF9TZXNzaW9uIE9SXG4gICAgc3lzdGVtQ2xhc3Nlcy5pbmRleE9mKGNsYXNzTmFtZSkgPiAtMSB8fFxuICAgIC8vIEJlIGEgam9pbiB0YWJsZSBPUlxuICAgIGpvaW5DbGFzc1JlZ2V4LnRlc3QoY2xhc3NOYW1lKSB8fFxuICAgIC8vIEluY2x1ZGUgb25seSBhbHBoYS1udW1lcmljIGFuZCB1bmRlcnNjb3JlcywgYW5kIG5vdCBzdGFydCB3aXRoIGFuIHVuZGVyc2NvcmUgb3IgbnVtYmVyXG4gICAgZmllbGROYW1lSXNWYWxpZChjbGFzc05hbWUsIGNsYXNzTmFtZSlcbiAgKTtcbn1cblxuLy8gVmFsaWQgZmllbGRzIG11c3QgYmUgYWxwaGEtbnVtZXJpYywgYW5kIG5vdCBzdGFydCB3aXRoIGFuIHVuZGVyc2NvcmUgb3IgbnVtYmVyXG4vLyBtdXN0IG5vdCBiZSBhIHJlc2VydmVkIGtleVxuZnVuY3Rpb24gZmllbGROYW1lSXNWYWxpZChmaWVsZE5hbWU6IHN0cmluZywgY2xhc3NOYW1lOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgaWYgKGNsYXNzTmFtZSAmJiBjbGFzc05hbWUgIT09ICdfSG9va3MnKSB7XG4gICAgaWYgKGZpZWxkTmFtZSA9PT0gJ2NsYXNzTmFtZScpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIGNsYXNzQW5kRmllbGRSZWdleC50ZXN0KGZpZWxkTmFtZSkgJiYgIWludmFsaWRDb2x1bW5zLmluY2x1ZGVzKGZpZWxkTmFtZSk7XG59XG5cbi8vIENoZWNrcyB0aGF0IGl0J3Mgbm90IHRyeWluZyB0byBjbG9iYmVyIG9uZSBvZiB0aGUgZGVmYXVsdCBmaWVsZHMgb2YgdGhlIGNsYXNzLlxuZnVuY3Rpb24gZmllbGROYW1lSXNWYWxpZEZvckNsYXNzKGZpZWxkTmFtZTogc3RyaW5nLCBjbGFzc05hbWU6IHN0cmluZyk6IGJvb2xlYW4ge1xuICBpZiAoIWZpZWxkTmFtZUlzVmFsaWQoZmllbGROYW1lLCBjbGFzc05hbWUpKSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG4gIGlmIChkZWZhdWx0Q29sdW1ucy5fRGVmYXVsdFtmaWVsZE5hbWVdKSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG4gIGlmIChkZWZhdWx0Q29sdW1uc1tjbGFzc05hbWVdICYmIGRlZmF1bHRDb2x1bW5zW2NsYXNzTmFtZV1bZmllbGROYW1lXSkge1xuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuICByZXR1cm4gdHJ1ZTtcbn1cblxuZnVuY3Rpb24gaW52YWxpZENsYXNzTmFtZU1lc3NhZ2UoY2xhc3NOYW1lOiBzdHJpbmcpOiBzdHJpbmcge1xuICByZXR1cm4gKFxuICAgICdJbnZhbGlkIGNsYXNzbmFtZTogJyArXG4gICAgY2xhc3NOYW1lICtcbiAgICAnLCBjbGFzc25hbWVzIGNhbiBvbmx5IGhhdmUgYWxwaGFudW1lcmljIGNoYXJhY3RlcnMgYW5kIF8sIGFuZCBtdXN0IHN0YXJ0IHdpdGggYW4gYWxwaGEgY2hhcmFjdGVyICdcbiAgKTtcbn1cblxuY29uc3QgaW52YWxpZEpzb25FcnJvciA9IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sICdpbnZhbGlkIEpTT04nKTtcbmNvbnN0IHZhbGlkTm9uUmVsYXRpb25PclBvaW50ZXJUeXBlcyA9IFtcbiAgJ051bWJlcicsXG4gICdTdHJpbmcnLFxuICAnQm9vbGVhbicsXG4gICdEYXRlJyxcbiAgJ09iamVjdCcsXG4gICdBcnJheScsXG4gICdHZW9Qb2ludCcsXG4gICdGaWxlJyxcbiAgJ0J5dGVzJyxcbiAgJ1BvbHlnb24nLFxuXTtcbi8vIFJldHVybnMgYW4gZXJyb3Igc3VpdGFibGUgZm9yIHRocm93aW5nIGlmIHRoZSB0eXBlIGlzIGludmFsaWRcbmNvbnN0IGZpZWxkVHlwZUlzSW52YWxpZCA9ICh7IHR5cGUsIHRhcmdldENsYXNzIH0pID0+IHtcbiAgaWYgKFsnUG9pbnRlcicsICdSZWxhdGlvbiddLmluZGV4T2YodHlwZSkgPj0gMCkge1xuICAgIGlmICghdGFyZ2V0Q2xhc3MpIHtcbiAgICAgIHJldHVybiBuZXcgUGFyc2UuRXJyb3IoMTM1LCBgdHlwZSAke3R5cGV9IG5lZWRzIGEgY2xhc3MgbmFtZWApO1xuICAgIH0gZWxzZSBpZiAodHlwZW9mIHRhcmdldENsYXNzICE9PSAnc3RyaW5nJykge1xuICAgICAgcmV0dXJuIGludmFsaWRKc29uRXJyb3I7XG4gICAgfSBlbHNlIGlmICghY2xhc3NOYW1lSXNWYWxpZCh0YXJnZXRDbGFzcykpIHtcbiAgICAgIHJldHVybiBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9DTEFTU19OQU1FLCBpbnZhbGlkQ2xhc3NOYW1lTWVzc2FnZSh0YXJnZXRDbGFzcykpO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgIH1cbiAgfVxuICBpZiAodHlwZW9mIHR5cGUgIT09ICdzdHJpbmcnKSB7XG4gICAgcmV0dXJuIGludmFsaWRKc29uRXJyb3I7XG4gIH1cbiAgaWYgKHZhbGlkTm9uUmVsYXRpb25PclBvaW50ZXJUeXBlcy5pbmRleE9mKHR5cGUpIDwgMCkge1xuICAgIHJldHVybiBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5DT1JSRUNUX1RZUEUsIGBpbnZhbGlkIGZpZWxkIHR5cGU6ICR7dHlwZX1gKTtcbiAgfVxuICByZXR1cm4gdW5kZWZpbmVkO1xufTtcblxuY29uc3QgY29udmVydFNjaGVtYVRvQWRhcHRlclNjaGVtYSA9IChzY2hlbWE6IGFueSkgPT4ge1xuICBzY2hlbWEgPSBpbmplY3REZWZhdWx0U2NoZW1hKHNjaGVtYSk7XG4gIGRlbGV0ZSBzY2hlbWEuZmllbGRzLkFDTDtcbiAgc2NoZW1hLmZpZWxkcy5fcnBlcm0gPSB7IHR5cGU6ICdBcnJheScgfTtcbiAgc2NoZW1hLmZpZWxkcy5fd3Blcm0gPSB7IHR5cGU6ICdBcnJheScgfTtcblxuICBpZiAoc2NoZW1hLmNsYXNzTmFtZSA9PT0gJ19Vc2VyJykge1xuICAgIGRlbGV0ZSBzY2hlbWEuZmllbGRzLnBhc3N3b3JkO1xuICAgIHNjaGVtYS5maWVsZHMuX2hhc2hlZF9wYXNzd29yZCA9IHsgdHlwZTogJ1N0cmluZycgfTtcbiAgfVxuXG4gIHJldHVybiBzY2hlbWE7XG59O1xuXG5jb25zdCBjb252ZXJ0QWRhcHRlclNjaGVtYVRvUGFyc2VTY2hlbWEgPSAoeyAuLi5zY2hlbWEgfSkgPT4ge1xuICBkZWxldGUgc2NoZW1hLmZpZWxkcy5fcnBlcm07XG4gIGRlbGV0ZSBzY2hlbWEuZmllbGRzLl93cGVybTtcblxuICBzY2hlbWEuZmllbGRzLkFDTCA9IHsgdHlwZTogJ0FDTCcgfTtcblxuICBpZiAoc2NoZW1hLmNsYXNzTmFtZSA9PT0gJ19Vc2VyJykge1xuICAgIGRlbGV0ZSBzY2hlbWEuZmllbGRzLmF1dGhEYXRhOyAvL0F1dGggZGF0YSBpcyBpbXBsaWNpdFxuICAgIGRlbGV0ZSBzY2hlbWEuZmllbGRzLl9oYXNoZWRfcGFzc3dvcmQ7XG4gICAgc2NoZW1hLmZpZWxkcy5wYXNzd29yZCA9IHsgdHlwZTogJ1N0cmluZycgfTtcbiAgfVxuXG4gIGlmIChzY2hlbWEuaW5kZXhlcyAmJiBPYmplY3Qua2V5cyhzY2hlbWEuaW5kZXhlcykubGVuZ3RoID09PSAwKSB7XG4gICAgZGVsZXRlIHNjaGVtYS5pbmRleGVzO1xuICB9XG5cbiAgcmV0dXJuIHNjaGVtYTtcbn07XG5cbmNsYXNzIFNjaGVtYURhdGEge1xuICBfX2RhdGE6IGFueTtcbiAgX19wcm90ZWN0ZWRGaWVsZHM6IGFueTtcbiAgY29uc3RydWN0b3IoYWxsU2NoZW1hcyA9IFtdLCBwcm90ZWN0ZWRGaWVsZHMgPSB7fSkge1xuICAgIHRoaXMuX19kYXRhID0ge307XG4gICAgdGhpcy5fX3Byb3RlY3RlZEZpZWxkcyA9IHByb3RlY3RlZEZpZWxkcztcbiAgICBhbGxTY2hlbWFzLmZvckVhY2goc2NoZW1hID0+IHtcbiAgICAgIGlmICh2b2xhdGlsZUNsYXNzZXMuaW5jbHVkZXMoc2NoZW1hLmNsYXNzTmFtZSkpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KHRoaXMsIHNjaGVtYS5jbGFzc05hbWUsIHtcbiAgICAgICAgZ2V0OiAoKSA9PiB7XG4gICAgICAgICAgaWYgKCF0aGlzLl9fZGF0YVtzY2hlbWEuY2xhc3NOYW1lXSkge1xuICAgICAgICAgICAgY29uc3QgZGF0YSA9IHt9O1xuICAgICAgICAgICAgZGF0YS5maWVsZHMgPSBpbmplY3REZWZhdWx0U2NoZW1hKHNjaGVtYSkuZmllbGRzO1xuICAgICAgICAgICAgZGF0YS5jbGFzc0xldmVsUGVybWlzc2lvbnMgPSBkZWVwY29weShzY2hlbWEuY2xhc3NMZXZlbFBlcm1pc3Npb25zKTtcbiAgICAgICAgICAgIGRhdGEuaW5kZXhlcyA9IHNjaGVtYS5pbmRleGVzO1xuXG4gICAgICAgICAgICBjb25zdCBjbGFzc1Byb3RlY3RlZEZpZWxkcyA9IHRoaXMuX19wcm90ZWN0ZWRGaWVsZHNbc2NoZW1hLmNsYXNzTmFtZV07XG4gICAgICAgICAgICBpZiAoY2xhc3NQcm90ZWN0ZWRGaWVsZHMpIHtcbiAgICAgICAgICAgICAgZm9yIChjb25zdCBrZXkgaW4gY2xhc3NQcm90ZWN0ZWRGaWVsZHMpIHtcbiAgICAgICAgICAgICAgICBjb25zdCB1bnEgPSBuZXcgU2V0KFtcbiAgICAgICAgICAgICAgICAgIC4uLihkYXRhLmNsYXNzTGV2ZWxQZXJtaXNzaW9ucy5wcm90ZWN0ZWRGaWVsZHNba2V5XSB8fCBbXSksXG4gICAgICAgICAgICAgICAgICAuLi5jbGFzc1Byb3RlY3RlZEZpZWxkc1trZXldLFxuICAgICAgICAgICAgICAgIF0pO1xuICAgICAgICAgICAgICAgIGRhdGEuY2xhc3NMZXZlbFBlcm1pc3Npb25zLnByb3RlY3RlZEZpZWxkc1trZXldID0gQXJyYXkuZnJvbSh1bnEpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHRoaXMuX19kYXRhW3NjaGVtYS5jbGFzc05hbWVdID0gZGF0YTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuIHRoaXMuX19kYXRhW3NjaGVtYS5jbGFzc05hbWVdO1xuICAgICAgICB9LFxuICAgICAgfSk7XG4gICAgfSk7XG5cbiAgICAvLyBJbmplY3QgdGhlIGluLW1lbW9yeSBjbGFzc2VzXG4gICAgdm9sYXRpbGVDbGFzc2VzLmZvckVhY2goY2xhc3NOYW1lID0+IHtcbiAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSh0aGlzLCBjbGFzc05hbWUsIHtcbiAgICAgICAgZ2V0OiAoKSA9PiB7XG4gICAgICAgICAgaWYgKCF0aGlzLl9fZGF0YVtjbGFzc05hbWVdKSB7XG4gICAgICAgICAgICBjb25zdCBzY2hlbWEgPSBpbmplY3REZWZhdWx0U2NoZW1hKHtcbiAgICAgICAgICAgICAgY2xhc3NOYW1lLFxuICAgICAgICAgICAgICBmaWVsZHM6IHt9LFxuICAgICAgICAgICAgICBjbGFzc0xldmVsUGVybWlzc2lvbnM6IHt9LFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBjb25zdCBkYXRhID0ge307XG4gICAgICAgICAgICBkYXRhLmZpZWxkcyA9IHNjaGVtYS5maWVsZHM7XG4gICAgICAgICAgICBkYXRhLmNsYXNzTGV2ZWxQZXJtaXNzaW9ucyA9IHNjaGVtYS5jbGFzc0xldmVsUGVybWlzc2lvbnM7XG4gICAgICAgICAgICBkYXRhLmluZGV4ZXMgPSBzY2hlbWEuaW5kZXhlcztcbiAgICAgICAgICAgIHRoaXMuX19kYXRhW2NsYXNzTmFtZV0gPSBkYXRhO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gdGhpcy5fX2RhdGFbY2xhc3NOYW1lXTtcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH0pO1xuICB9XG59XG5cbmNvbnN0IGluamVjdERlZmF1bHRTY2hlbWEgPSAoeyBjbGFzc05hbWUsIGZpZWxkcywgY2xhc3NMZXZlbFBlcm1pc3Npb25zLCBpbmRleGVzIH06IFNjaGVtYSkgPT4ge1xuICBjb25zdCBkZWZhdWx0U2NoZW1hOiBTY2hlbWEgPSB7XG4gICAgY2xhc3NOYW1lLFxuICAgIGZpZWxkczoge1xuICAgICAgLi4uZGVmYXVsdENvbHVtbnMuX0RlZmF1bHQsXG4gICAgICAuLi4oZGVmYXVsdENvbHVtbnNbY2xhc3NOYW1lXSB8fCB7fSksXG4gICAgICAuLi5maWVsZHMsXG4gICAgfSxcbiAgICBjbGFzc0xldmVsUGVybWlzc2lvbnMsXG4gIH07XG4gIGlmIChpbmRleGVzICYmIE9iamVjdC5rZXlzKGluZGV4ZXMpLmxlbmd0aCAhPT0gMCkge1xuICAgIGRlZmF1bHRTY2hlbWEuaW5kZXhlcyA9IGluZGV4ZXM7XG4gIH1cbiAgcmV0dXJuIGRlZmF1bHRTY2hlbWE7XG59O1xuXG5jb25zdCBfSG9va3NTY2hlbWEgPSB7IGNsYXNzTmFtZTogJ19Ib29rcycsIGZpZWxkczogZGVmYXVsdENvbHVtbnMuX0hvb2tzIH07XG5jb25zdCBfR2xvYmFsQ29uZmlnU2NoZW1hID0ge1xuICBjbGFzc05hbWU6ICdfR2xvYmFsQ29uZmlnJyxcbiAgZmllbGRzOiBkZWZhdWx0Q29sdW1ucy5fR2xvYmFsQ29uZmlnLFxufTtcbmNvbnN0IF9HcmFwaFFMQ29uZmlnU2NoZW1hID0ge1xuICBjbGFzc05hbWU6ICdfR3JhcGhRTENvbmZpZycsXG4gIGZpZWxkczogZGVmYXVsdENvbHVtbnMuX0dyYXBoUUxDb25maWcsXG59O1xuY29uc3QgX1B1c2hTdGF0dXNTY2hlbWEgPSBjb252ZXJ0U2NoZW1hVG9BZGFwdGVyU2NoZW1hKFxuICBpbmplY3REZWZhdWx0U2NoZW1hKHtcbiAgICBjbGFzc05hbWU6ICdfUHVzaFN0YXR1cycsXG4gICAgZmllbGRzOiB7fSxcbiAgICBjbGFzc0xldmVsUGVybWlzc2lvbnM6IHt9LFxuICB9KVxuKTtcbmNvbnN0IF9Kb2JTdGF0dXNTY2hlbWEgPSBjb252ZXJ0U2NoZW1hVG9BZGFwdGVyU2NoZW1hKFxuICBpbmplY3REZWZhdWx0U2NoZW1hKHtcbiAgICBjbGFzc05hbWU6ICdfSm9iU3RhdHVzJyxcbiAgICBmaWVsZHM6IHt9LFxuICAgIGNsYXNzTGV2ZWxQZXJtaXNzaW9uczoge30sXG4gIH0pXG4pO1xuY29uc3QgX0pvYlNjaGVkdWxlU2NoZW1hID0gY29udmVydFNjaGVtYVRvQWRhcHRlclNjaGVtYShcbiAgaW5qZWN0RGVmYXVsdFNjaGVtYSh7XG4gICAgY2xhc3NOYW1lOiAnX0pvYlNjaGVkdWxlJyxcbiAgICBmaWVsZHM6IHt9LFxuICAgIGNsYXNzTGV2ZWxQZXJtaXNzaW9uczoge30sXG4gIH0pXG4pO1xuY29uc3QgX0F1ZGllbmNlU2NoZW1hID0gY29udmVydFNjaGVtYVRvQWRhcHRlclNjaGVtYShcbiAgaW5qZWN0RGVmYXVsdFNjaGVtYSh7XG4gICAgY2xhc3NOYW1lOiAnX0F1ZGllbmNlJyxcbiAgICBmaWVsZHM6IGRlZmF1bHRDb2x1bW5zLl9BdWRpZW5jZSxcbiAgICBjbGFzc0xldmVsUGVybWlzc2lvbnM6IHt9LFxuICB9KVxuKTtcbmNvbnN0IF9JZGVtcG90ZW5jeVNjaGVtYSA9IGNvbnZlcnRTY2hlbWFUb0FkYXB0ZXJTY2hlbWEoXG4gIGluamVjdERlZmF1bHRTY2hlbWEoe1xuICAgIGNsYXNzTmFtZTogJ19JZGVtcG90ZW5jeScsXG4gICAgZmllbGRzOiBkZWZhdWx0Q29sdW1ucy5fSWRlbXBvdGVuY3ksXG4gICAgY2xhc3NMZXZlbFBlcm1pc3Npb25zOiB7fSxcbiAgfSlcbik7XG5jb25zdCBWb2xhdGlsZUNsYXNzZXNTY2hlbWFzID0gW1xuICBfSG9va3NTY2hlbWEsXG4gIF9Kb2JTdGF0dXNTY2hlbWEsXG4gIF9Kb2JTY2hlZHVsZVNjaGVtYSxcbiAgX1B1c2hTdGF0dXNTY2hlbWEsXG4gIF9HbG9iYWxDb25maWdTY2hlbWEsXG4gIF9HcmFwaFFMQ29uZmlnU2NoZW1hLFxuICBfQXVkaWVuY2VTY2hlbWEsXG4gIF9JZGVtcG90ZW5jeVNjaGVtYSxcbl07XG5cbmNvbnN0IGRiVHlwZU1hdGNoZXNPYmplY3RUeXBlID0gKGRiVHlwZTogU2NoZW1hRmllbGQgfCBzdHJpbmcsIG9iamVjdFR5cGU6IFNjaGVtYUZpZWxkKSA9PiB7XG4gIGlmIChkYlR5cGUudHlwZSAhPT0gb2JqZWN0VHlwZS50eXBlKSByZXR1cm4gZmFsc2U7XG4gIGlmIChkYlR5cGUudGFyZ2V0Q2xhc3MgIT09IG9iamVjdFR5cGUudGFyZ2V0Q2xhc3MpIHJldHVybiBmYWxzZTtcbiAgaWYgKGRiVHlwZSA9PT0gb2JqZWN0VHlwZS50eXBlKSByZXR1cm4gdHJ1ZTtcbiAgaWYgKGRiVHlwZS50eXBlID09PSBvYmplY3RUeXBlLnR5cGUpIHJldHVybiB0cnVlO1xuICByZXR1cm4gZmFsc2U7XG59O1xuXG5jb25zdCB0eXBlVG9TdHJpbmcgPSAodHlwZTogU2NoZW1hRmllbGQgfCBzdHJpbmcpOiBzdHJpbmcgPT4ge1xuICBpZiAodHlwZW9mIHR5cGUgPT09ICdzdHJpbmcnKSB7XG4gICAgcmV0dXJuIHR5cGU7XG4gIH1cbiAgaWYgKHR5cGUudGFyZ2V0Q2xhc3MpIHtcbiAgICByZXR1cm4gYCR7dHlwZS50eXBlfTwke3R5cGUudGFyZ2V0Q2xhc3N9PmA7XG4gIH1cbiAgcmV0dXJuIGAke3R5cGUudHlwZX1gO1xufTtcblxuLy8gU3RvcmVzIHRoZSBlbnRpcmUgc2NoZW1hIG9mIHRoZSBhcHAgaW4gYSB3ZWlyZCBoeWJyaWQgZm9ybWF0IHNvbWV3aGVyZSBiZXR3ZWVuXG4vLyB0aGUgbW9uZ28gZm9ybWF0IGFuZCB0aGUgUGFyc2UgZm9ybWF0LiBTb29uLCB0aGlzIHdpbGwgYWxsIGJlIFBhcnNlIGZvcm1hdC5cbmV4cG9ydCBkZWZhdWx0IGNsYXNzIFNjaGVtYUNvbnRyb2xsZXIge1xuICBfZGJBZGFwdGVyOiBTdG9yYWdlQWRhcHRlcjtcbiAgc2NoZW1hRGF0YTogeyBbc3RyaW5nXTogU2NoZW1hIH07XG4gIHJlbG9hZERhdGFQcm9taXNlOiA/UHJvbWlzZTxhbnk+O1xuICBwcm90ZWN0ZWRGaWVsZHM6IGFueTtcbiAgdXNlcklkUmVnRXg6IFJlZ0V4cDtcblxuICBjb25zdHJ1Y3RvcihkYXRhYmFzZUFkYXB0ZXI6IFN0b3JhZ2VBZGFwdGVyKSB7XG4gICAgdGhpcy5fZGJBZGFwdGVyID0gZGF0YWJhc2VBZGFwdGVyO1xuICAgIHRoaXMuc2NoZW1hRGF0YSA9IG5ldyBTY2hlbWFEYXRhKFNjaGVtYUNhY2hlLmFsbCgpLCB0aGlzLnByb3RlY3RlZEZpZWxkcyk7XG4gICAgdGhpcy5wcm90ZWN0ZWRGaWVsZHMgPSBDb25maWcuZ2V0KFBhcnNlLmFwcGxpY2F0aW9uSWQpLnByb3RlY3RlZEZpZWxkcztcblxuICAgIGNvbnN0IGN1c3RvbUlkcyA9IENvbmZpZy5nZXQoUGFyc2UuYXBwbGljYXRpb25JZCkuYWxsb3dDdXN0b21PYmplY3RJZDtcblxuICAgIGNvbnN0IGN1c3RvbUlkUmVnRXggPSAvXi57MSx9JC91OyAvLyAxKyBjaGFyc1xuICAgIGNvbnN0IGF1dG9JZFJlZ0V4ID0gL15bYS16QS1aMC05XXsxLH0kLztcblxuICAgIHRoaXMudXNlcklkUmVnRXggPSBjdXN0b21JZHMgPyBjdXN0b21JZFJlZ0V4IDogYXV0b0lkUmVnRXg7XG5cbiAgICB0aGlzLl9kYkFkYXB0ZXIud2F0Y2goKCkgPT4ge1xuICAgICAgdGhpcy5yZWxvYWREYXRhKHsgY2xlYXJDYWNoZTogdHJ1ZSB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIHJlbG9hZERhdGEob3B0aW9uczogTG9hZFNjaGVtYU9wdGlvbnMgPSB7IGNsZWFyQ2FjaGU6IGZhbHNlIH0pOiBQcm9taXNlPGFueT4ge1xuICAgIGlmICh0aGlzLnJlbG9hZERhdGFQcm9taXNlICYmICFvcHRpb25zLmNsZWFyQ2FjaGUpIHtcbiAgICAgIHJldHVybiB0aGlzLnJlbG9hZERhdGFQcm9taXNlO1xuICAgIH1cbiAgICB0aGlzLnJlbG9hZERhdGFQcm9taXNlID0gdGhpcy5nZXRBbGxDbGFzc2VzKG9wdGlvbnMpXG4gICAgICAudGhlbihcbiAgICAgICAgYWxsU2NoZW1hcyA9PiB7XG4gICAgICAgICAgdGhpcy5zY2hlbWFEYXRhID0gbmV3IFNjaGVtYURhdGEoYWxsU2NoZW1hcywgdGhpcy5wcm90ZWN0ZWRGaWVsZHMpO1xuICAgICAgICAgIGRlbGV0ZSB0aGlzLnJlbG9hZERhdGFQcm9taXNlO1xuICAgICAgICB9LFxuICAgICAgICBlcnIgPT4ge1xuICAgICAgICAgIHRoaXMuc2NoZW1hRGF0YSA9IG5ldyBTY2hlbWFEYXRhKCk7XG4gICAgICAgICAgZGVsZXRlIHRoaXMucmVsb2FkRGF0YVByb21pc2U7XG4gICAgICAgICAgdGhyb3cgZXJyO1xuICAgICAgICB9XG4gICAgICApXG4gICAgICAudGhlbigoKSA9PiB7fSk7XG4gICAgcmV0dXJuIHRoaXMucmVsb2FkRGF0YVByb21pc2U7XG4gIH1cblxuICBnZXRBbGxDbGFzc2VzKG9wdGlvbnM6IExvYWRTY2hlbWFPcHRpb25zID0geyBjbGVhckNhY2hlOiBmYWxzZSB9KTogUHJvbWlzZTxBcnJheTxTY2hlbWE+PiB7XG4gICAgaWYgKG9wdGlvbnMuY2xlYXJDYWNoZSkge1xuICAgICAgcmV0dXJuIHRoaXMuc2V0QWxsQ2xhc3NlcygpO1xuICAgIH1cbiAgICBjb25zdCBjYWNoZWQgPSBTY2hlbWFDYWNoZS5hbGwoKTtcbiAgICBpZiAoY2FjaGVkICYmIGNhY2hlZC5sZW5ndGgpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoY2FjaGVkKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuc2V0QWxsQ2xhc3NlcygpO1xuICB9XG5cbiAgc2V0QWxsQ2xhc3NlcygpOiBQcm9taXNlPEFycmF5PFNjaGVtYT4+IHtcbiAgICByZXR1cm4gdGhpcy5fZGJBZGFwdGVyXG4gICAgICAuZ2V0QWxsQ2xhc3NlcygpXG4gICAgICAudGhlbihhbGxTY2hlbWFzID0+IGFsbFNjaGVtYXMubWFwKGluamVjdERlZmF1bHRTY2hlbWEpKVxuICAgICAgLnRoZW4oYWxsU2NoZW1hcyA9PiB7XG4gICAgICAgIFNjaGVtYUNhY2hlLnB1dChhbGxTY2hlbWFzKTtcbiAgICAgICAgcmV0dXJuIGFsbFNjaGVtYXM7XG4gICAgICB9KTtcbiAgfVxuXG4gIGdldE9uZVNjaGVtYShcbiAgICBjbGFzc05hbWU6IHN0cmluZyxcbiAgICBhbGxvd1ZvbGF0aWxlQ2xhc3NlczogYm9vbGVhbiA9IGZhbHNlLFxuICAgIG9wdGlvbnM6IExvYWRTY2hlbWFPcHRpb25zID0geyBjbGVhckNhY2hlOiBmYWxzZSB9XG4gICk6IFByb21pc2U8U2NoZW1hPiB7XG4gICAgaWYgKG9wdGlvbnMuY2xlYXJDYWNoZSkge1xuICAgICAgU2NoZW1hQ2FjaGUuY2xlYXIoKTtcbiAgICB9XG4gICAgaWYgKGFsbG93Vm9sYXRpbGVDbGFzc2VzICYmIHZvbGF0aWxlQ2xhc3Nlcy5pbmRleE9mKGNsYXNzTmFtZSkgPiAtMSkge1xuICAgICAgY29uc3QgZGF0YSA9IHRoaXMuc2NoZW1hRGF0YVtjbGFzc05hbWVdO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh7XG4gICAgICAgIGNsYXNzTmFtZSxcbiAgICAgICAgZmllbGRzOiBkYXRhLmZpZWxkcyxcbiAgICAgICAgY2xhc3NMZXZlbFBlcm1pc3Npb25zOiBkYXRhLmNsYXNzTGV2ZWxQZXJtaXNzaW9ucyxcbiAgICAgICAgaW5kZXhlczogZGF0YS5pbmRleGVzLFxuICAgICAgfSk7XG4gICAgfVxuICAgIGNvbnN0IGNhY2hlZCA9IFNjaGVtYUNhY2hlLmdldChjbGFzc05hbWUpO1xuICAgIGlmIChjYWNoZWQgJiYgIW9wdGlvbnMuY2xlYXJDYWNoZSkge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShjYWNoZWQpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5zZXRBbGxDbGFzc2VzKCkudGhlbihhbGxTY2hlbWFzID0+IHtcbiAgICAgIGNvbnN0IG9uZVNjaGVtYSA9IGFsbFNjaGVtYXMuZmluZChzY2hlbWEgPT4gc2NoZW1hLmNsYXNzTmFtZSA9PT0gY2xhc3NOYW1lKTtcbiAgICAgIGlmICghb25lU2NoZW1hKSB7XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdCh1bmRlZmluZWQpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIG9uZVNjaGVtYTtcbiAgICB9KTtcbiAgfVxuXG4gIC8vIENyZWF0ZSBhIG5ldyBjbGFzcyB0aGF0IGluY2x1ZGVzIHRoZSB0aHJlZSBkZWZhdWx0IGZpZWxkcy5cbiAgLy8gQUNMIGlzIGFuIGltcGxpY2l0IGNvbHVtbiB0aGF0IGRvZXMgbm90IGdldCBhbiBlbnRyeSBpbiB0aGVcbiAgLy8gX1NDSEVNQVMgZGF0YWJhc2UuIFJldHVybnMgYSBwcm9taXNlIHRoYXQgcmVzb2x2ZXMgd2l0aCB0aGVcbiAgLy8gY3JlYXRlZCBzY2hlbWEsIGluIG1vbmdvIGZvcm1hdC5cbiAgLy8gb24gc3VjY2VzcywgYW5kIHJlamVjdHMgd2l0aCBhbiBlcnJvciBvbiBmYWlsLiBFbnN1cmUgeW91XG4gIC8vIGhhdmUgYXV0aG9yaXphdGlvbiAobWFzdGVyIGtleSwgb3IgY2xpZW50IGNsYXNzIGNyZWF0aW9uXG4gIC8vIGVuYWJsZWQpIGJlZm9yZSBjYWxsaW5nIHRoaXMgZnVuY3Rpb24uXG4gIGFzeW5jIGFkZENsYXNzSWZOb3RFeGlzdHMoXG4gICAgY2xhc3NOYW1lOiBzdHJpbmcsXG4gICAgZmllbGRzOiBTY2hlbWFGaWVsZHMgPSB7fSxcbiAgICBjbGFzc0xldmVsUGVybWlzc2lvbnM6IGFueSxcbiAgICBpbmRleGVzOiBhbnkgPSB7fVxuICApOiBQcm9taXNlPHZvaWQgfCBTY2hlbWE+IHtcbiAgICB2YXIgdmFsaWRhdGlvbkVycm9yID0gdGhpcy52YWxpZGF0ZU5ld0NsYXNzKGNsYXNzTmFtZSwgZmllbGRzLCBjbGFzc0xldmVsUGVybWlzc2lvbnMpO1xuICAgIGlmICh2YWxpZGF0aW9uRXJyb3IpIHtcbiAgICAgIGlmICh2YWxpZGF0aW9uRXJyb3IgaW5zdGFuY2VvZiBQYXJzZS5FcnJvcikge1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QodmFsaWRhdGlvbkVycm9yKTtcbiAgICAgIH0gZWxzZSBpZiAodmFsaWRhdGlvbkVycm9yLmNvZGUgJiYgdmFsaWRhdGlvbkVycm9yLmVycm9yKSB7XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChuZXcgUGFyc2UuRXJyb3IodmFsaWRhdGlvbkVycm9yLmNvZGUsIHZhbGlkYXRpb25FcnJvci5lcnJvcikpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHZhbGlkYXRpb25FcnJvcik7XG4gICAgfVxuICAgIHRyeSB7XG4gICAgICBjb25zdCBhZGFwdGVyU2NoZW1hID0gYXdhaXQgdGhpcy5fZGJBZGFwdGVyLmNyZWF0ZUNsYXNzKFxuICAgICAgICBjbGFzc05hbWUsXG4gICAgICAgIGNvbnZlcnRTY2hlbWFUb0FkYXB0ZXJTY2hlbWEoe1xuICAgICAgICAgIGZpZWxkcyxcbiAgICAgICAgICBjbGFzc0xldmVsUGVybWlzc2lvbnMsXG4gICAgICAgICAgaW5kZXhlcyxcbiAgICAgICAgICBjbGFzc05hbWUsXG4gICAgICAgIH0pXG4gICAgICApO1xuICAgICAgLy8gVE9ETzogUmVtb3ZlIGJ5IHVwZGF0aW5nIHNjaGVtYSBjYWNoZSBkaXJlY3RseVxuICAgICAgYXdhaXQgdGhpcy5yZWxvYWREYXRhKHsgY2xlYXJDYWNoZTogdHJ1ZSB9KTtcbiAgICAgIGNvbnN0IHBhcnNlU2NoZW1hID0gY29udmVydEFkYXB0ZXJTY2hlbWFUb1BhcnNlU2NoZW1hKGFkYXB0ZXJTY2hlbWEpO1xuICAgICAgcmV0dXJuIHBhcnNlU2NoZW1hO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBpZiAoZXJyb3IgJiYgZXJyb3IuY29kZSA9PT0gUGFyc2UuRXJyb3IuRFVQTElDQVRFX1ZBTFVFKSB7XG4gICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0NMQVNTX05BTUUsIGBDbGFzcyAke2NsYXNzTmFtZX0gYWxyZWFkeSBleGlzdHMuYCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICB1cGRhdGVDbGFzcyhcbiAgICBjbGFzc05hbWU6IHN0cmluZyxcbiAgICBzdWJtaXR0ZWRGaWVsZHM6IFNjaGVtYUZpZWxkcyxcbiAgICBjbGFzc0xldmVsUGVybWlzc2lvbnM6IGFueSxcbiAgICBpbmRleGVzOiBhbnksXG4gICAgZGF0YWJhc2U6IERhdGFiYXNlQ29udHJvbGxlclxuICApIHtcbiAgICByZXR1cm4gdGhpcy5nZXRPbmVTY2hlbWEoY2xhc3NOYW1lKVxuICAgICAgLnRoZW4oc2NoZW1hID0+IHtcbiAgICAgICAgY29uc3QgZXhpc3RpbmdGaWVsZHMgPSBzY2hlbWEuZmllbGRzO1xuICAgICAgICBPYmplY3Qua2V5cyhzdWJtaXR0ZWRGaWVsZHMpLmZvckVhY2gobmFtZSA9PiB7XG4gICAgICAgICAgY29uc3QgZmllbGQgPSBzdWJtaXR0ZWRGaWVsZHNbbmFtZV07XG4gICAgICAgICAgaWYgKGV4aXN0aW5nRmllbGRzW25hbWVdICYmIGZpZWxkLl9fb3AgIT09ICdEZWxldGUnKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoMjU1LCBgRmllbGQgJHtuYW1lfSBleGlzdHMsIGNhbm5vdCB1cGRhdGUuYCk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGlmICghZXhpc3RpbmdGaWVsZHNbbmFtZV0gJiYgZmllbGQuX19vcCA9PT0gJ0RlbGV0ZScpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcigyNTUsIGBGaWVsZCAke25hbWV9IGRvZXMgbm90IGV4aXN0LCBjYW5ub3QgZGVsZXRlLmApO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG5cbiAgICAgICAgZGVsZXRlIGV4aXN0aW5nRmllbGRzLl9ycGVybTtcbiAgICAgICAgZGVsZXRlIGV4aXN0aW5nRmllbGRzLl93cGVybTtcbiAgICAgICAgY29uc3QgbmV3U2NoZW1hID0gYnVpbGRNZXJnZWRTY2hlbWFPYmplY3QoZXhpc3RpbmdGaWVsZHMsIHN1Ym1pdHRlZEZpZWxkcyk7XG4gICAgICAgIGNvbnN0IGRlZmF1bHRGaWVsZHMgPSBkZWZhdWx0Q29sdW1uc1tjbGFzc05hbWVdIHx8IGRlZmF1bHRDb2x1bW5zLl9EZWZhdWx0O1xuICAgICAgICBjb25zdCBmdWxsTmV3U2NoZW1hID0gT2JqZWN0LmFzc2lnbih7fSwgbmV3U2NoZW1hLCBkZWZhdWx0RmllbGRzKTtcbiAgICAgICAgY29uc3QgdmFsaWRhdGlvbkVycm9yID0gdGhpcy52YWxpZGF0ZVNjaGVtYURhdGEoXG4gICAgICAgICAgY2xhc3NOYW1lLFxuICAgICAgICAgIG5ld1NjaGVtYSxcbiAgICAgICAgICBjbGFzc0xldmVsUGVybWlzc2lvbnMsXG4gICAgICAgICAgT2JqZWN0LmtleXMoZXhpc3RpbmdGaWVsZHMpXG4gICAgICAgICk7XG4gICAgICAgIGlmICh2YWxpZGF0aW9uRXJyb3IpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IodmFsaWRhdGlvbkVycm9yLmNvZGUsIHZhbGlkYXRpb25FcnJvci5lcnJvcik7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBGaW5hbGx5IHdlIGhhdmUgY2hlY2tlZCB0byBtYWtlIHN1cmUgdGhlIHJlcXVlc3QgaXMgdmFsaWQgYW5kIHdlIGNhbiBzdGFydCBkZWxldGluZyBmaWVsZHMuXG4gICAgICAgIC8vIERvIGFsbCBkZWxldGlvbnMgZmlyc3QsIHRoZW4gYSBzaW5nbGUgc2F2ZSB0byBfU0NIRU1BIGNvbGxlY3Rpb24gdG8gaGFuZGxlIGFsbCBhZGRpdGlvbnMuXG4gICAgICAgIGNvbnN0IGRlbGV0ZWRGaWVsZHM6IHN0cmluZ1tdID0gW107XG4gICAgICAgIGNvbnN0IGluc2VydGVkRmllbGRzID0gW107XG4gICAgICAgIE9iamVjdC5rZXlzKHN1Ym1pdHRlZEZpZWxkcykuZm9yRWFjaChmaWVsZE5hbWUgPT4ge1xuICAgICAgICAgIGlmIChzdWJtaXR0ZWRGaWVsZHNbZmllbGROYW1lXS5fX29wID09PSAnRGVsZXRlJykge1xuICAgICAgICAgICAgZGVsZXRlZEZpZWxkcy5wdXNoKGZpZWxkTmFtZSk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGluc2VydGVkRmllbGRzLnB1c2goZmllbGROYW1lKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuXG4gICAgICAgIGxldCBkZWxldGVQcm9taXNlID0gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgIGlmIChkZWxldGVkRmllbGRzLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICBkZWxldGVQcm9taXNlID0gdGhpcy5kZWxldGVGaWVsZHMoZGVsZXRlZEZpZWxkcywgY2xhc3NOYW1lLCBkYXRhYmFzZSk7XG4gICAgICAgIH1cbiAgICAgICAgbGV0IGVuZm9yY2VGaWVsZHMgPSBbXTtcbiAgICAgICAgcmV0dXJuIChcbiAgICAgICAgICBkZWxldGVQcm9taXNlIC8vIERlbGV0ZSBFdmVyeXRoaW5nXG4gICAgICAgICAgICAudGhlbigoKSA9PiB0aGlzLnJlbG9hZERhdGEoeyBjbGVhckNhY2hlOiB0cnVlIH0pKSAvLyBSZWxvYWQgb3VyIFNjaGVtYSwgc28gd2UgaGF2ZSBhbGwgdGhlIG5ldyB2YWx1ZXNcbiAgICAgICAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgICAgICAgY29uc3QgcHJvbWlzZXMgPSBpbnNlcnRlZEZpZWxkcy5tYXAoZmllbGROYW1lID0+IHtcbiAgICAgICAgICAgICAgICBjb25zdCB0eXBlID0gc3VibWl0dGVkRmllbGRzW2ZpZWxkTmFtZV07XG4gICAgICAgICAgICAgICAgcmV0dXJuIHRoaXMuZW5mb3JjZUZpZWxkRXhpc3RzKGNsYXNzTmFtZSwgZmllbGROYW1lLCB0eXBlKTtcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLmFsbChwcm9taXNlcyk7XG4gICAgICAgICAgICB9KVxuICAgICAgICAgICAgLnRoZW4ocmVzdWx0cyA9PiB7XG4gICAgICAgICAgICAgIGVuZm9yY2VGaWVsZHMgPSByZXN1bHRzLmZpbHRlcihyZXN1bHQgPT4gISFyZXN1bHQpO1xuICAgICAgICAgICAgICByZXR1cm4gdGhpcy5zZXRQZXJtaXNzaW9ucyhjbGFzc05hbWUsIGNsYXNzTGV2ZWxQZXJtaXNzaW9ucywgbmV3U2NoZW1hKTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAudGhlbigoKSA9PlxuICAgICAgICAgICAgICB0aGlzLl9kYkFkYXB0ZXIuc2V0SW5kZXhlc1dpdGhTY2hlbWFGb3JtYXQoXG4gICAgICAgICAgICAgICAgY2xhc3NOYW1lLFxuICAgICAgICAgICAgICAgIGluZGV4ZXMsXG4gICAgICAgICAgICAgICAgc2NoZW1hLmluZGV4ZXMsXG4gICAgICAgICAgICAgICAgZnVsbE5ld1NjaGVtYVxuICAgICAgICAgICAgICApXG4gICAgICAgICAgICApXG4gICAgICAgICAgICAudGhlbigoKSA9PiB0aGlzLnJlbG9hZERhdGEoeyBjbGVhckNhY2hlOiB0cnVlIH0pKVxuICAgICAgICAgICAgLy9UT0RPOiBNb3ZlIHRoaXMgbG9naWMgaW50byB0aGUgZGF0YWJhc2UgYWRhcHRlclxuICAgICAgICAgICAgLnRoZW4oKCkgPT4ge1xuICAgICAgICAgICAgICB0aGlzLmVuc3VyZUZpZWxkcyhlbmZvcmNlRmllbGRzKTtcbiAgICAgICAgICAgICAgY29uc3Qgc2NoZW1hID0gdGhpcy5zY2hlbWFEYXRhW2NsYXNzTmFtZV07XG4gICAgICAgICAgICAgIGNvbnN0IHJlbG9hZGVkU2NoZW1hOiBTY2hlbWEgPSB7XG4gICAgICAgICAgICAgICAgY2xhc3NOYW1lOiBjbGFzc05hbWUsXG4gICAgICAgICAgICAgICAgZmllbGRzOiBzY2hlbWEuZmllbGRzLFxuICAgICAgICAgICAgICAgIGNsYXNzTGV2ZWxQZXJtaXNzaW9uczogc2NoZW1hLmNsYXNzTGV2ZWxQZXJtaXNzaW9ucyxcbiAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgICAgaWYgKHNjaGVtYS5pbmRleGVzICYmIE9iamVjdC5rZXlzKHNjaGVtYS5pbmRleGVzKS5sZW5ndGggIT09IDApIHtcbiAgICAgICAgICAgICAgICByZWxvYWRlZFNjaGVtYS5pbmRleGVzID0gc2NoZW1hLmluZGV4ZXM7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgcmV0dXJuIHJlbG9hZGVkU2NoZW1hO1xuICAgICAgICAgICAgfSlcbiAgICAgICAgKTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICBpZiAoZXJyb3IgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfQ0xBU1NfTkFNRSxcbiAgICAgICAgICAgIGBDbGFzcyAke2NsYXNzTmFtZX0gZG9lcyBub3QgZXhpc3QuYFxuICAgICAgICAgICk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICB9XG5cbiAgLy8gUmV0dXJucyBhIHByb21pc2UgdGhhdCByZXNvbHZlcyBzdWNjZXNzZnVsbHkgdG8gdGhlIG5ldyBzY2hlbWFcbiAgLy8gb2JqZWN0IG9yIGZhaWxzIHdpdGggYSByZWFzb24uXG4gIGVuZm9yY2VDbGFzc0V4aXN0cyhjbGFzc05hbWU6IHN0cmluZyk6IFByb21pc2U8U2NoZW1hQ29udHJvbGxlcj4ge1xuICAgIGlmICh0aGlzLnNjaGVtYURhdGFbY2xhc3NOYW1lXSkge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0aGlzKTtcbiAgICB9XG4gICAgLy8gV2UgZG9uJ3QgaGF2ZSB0aGlzIGNsYXNzLiBVcGRhdGUgdGhlIHNjaGVtYVxuICAgIHJldHVybiAoXG4gICAgICAvLyBUaGUgc2NoZW1hIHVwZGF0ZSBzdWNjZWVkZWQuIFJlbG9hZCB0aGUgc2NoZW1hXG4gICAgICB0aGlzLmFkZENsYXNzSWZOb3RFeGlzdHMoY2xhc3NOYW1lKVxuICAgICAgICAuY2F0Y2goKCkgPT4ge1xuICAgICAgICAgIC8vIFRoZSBzY2hlbWEgdXBkYXRlIGZhaWxlZC4gVGhpcyBjYW4gYmUgb2theSAtIGl0IG1pZ2h0XG4gICAgICAgICAgLy8gaGF2ZSBmYWlsZWQgYmVjYXVzZSB0aGVyZSdzIGEgcmFjZSBjb25kaXRpb24gYW5kIGEgZGlmZmVyZW50XG4gICAgICAgICAgLy8gY2xpZW50IGlzIG1ha2luZyB0aGUgZXhhY3Qgc2FtZSBzY2hlbWEgdXBkYXRlIHRoYXQgd2Ugd2FudC5cbiAgICAgICAgICAvLyBTbyBqdXN0IHJlbG9hZCB0aGUgc2NoZW1hLlxuICAgICAgICAgIHJldHVybiB0aGlzLnJlbG9hZERhdGEoeyBjbGVhckNhY2hlOiB0cnVlIH0pO1xuICAgICAgICB9KVxuICAgICAgICAudGhlbigoKSA9PiB7XG4gICAgICAgICAgLy8gRW5zdXJlIHRoYXQgdGhlIHNjaGVtYSBub3cgdmFsaWRhdGVzXG4gICAgICAgICAgaWYgKHRoaXMuc2NoZW1hRGF0YVtjbGFzc05hbWVdKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcztcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgYEZhaWxlZCB0byBhZGQgJHtjbGFzc05hbWV9YCk7XG4gICAgICAgICAgfVxuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goKCkgPT4ge1xuICAgICAgICAgIC8vIFRoZSBzY2hlbWEgc3RpbGwgZG9lc24ndCB2YWxpZGF0ZS4gR2l2ZSB1cFxuICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sICdzY2hlbWEgY2xhc3MgbmFtZSBkb2VzIG5vdCByZXZhbGlkYXRlJyk7XG4gICAgICAgIH0pXG4gICAgKTtcbiAgfVxuXG4gIHZhbGlkYXRlTmV3Q2xhc3MoY2xhc3NOYW1lOiBzdHJpbmcsIGZpZWxkczogU2NoZW1hRmllbGRzID0ge30sIGNsYXNzTGV2ZWxQZXJtaXNzaW9uczogYW55KTogYW55IHtcbiAgICBpZiAodGhpcy5zY2hlbWFEYXRhW2NsYXNzTmFtZV0pIHtcbiAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0NMQVNTX05BTUUsIGBDbGFzcyAke2NsYXNzTmFtZX0gYWxyZWFkeSBleGlzdHMuYCk7XG4gICAgfVxuICAgIGlmICghY2xhc3NOYW1lSXNWYWxpZChjbGFzc05hbWUpKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBjb2RlOiBQYXJzZS5FcnJvci5JTlZBTElEX0NMQVNTX05BTUUsXG4gICAgICAgIGVycm9yOiBpbnZhbGlkQ2xhc3NOYW1lTWVzc2FnZShjbGFzc05hbWUpLFxuICAgICAgfTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMudmFsaWRhdGVTY2hlbWFEYXRhKGNsYXNzTmFtZSwgZmllbGRzLCBjbGFzc0xldmVsUGVybWlzc2lvbnMsIFtdKTtcbiAgfVxuXG4gIHZhbGlkYXRlU2NoZW1hRGF0YShcbiAgICBjbGFzc05hbWU6IHN0cmluZyxcbiAgICBmaWVsZHM6IFNjaGVtYUZpZWxkcyxcbiAgICBjbGFzc0xldmVsUGVybWlzc2lvbnM6IENsYXNzTGV2ZWxQZXJtaXNzaW9ucyxcbiAgICBleGlzdGluZ0ZpZWxkTmFtZXM6IEFycmF5PHN0cmluZz5cbiAgKSB7XG4gICAgZm9yIChjb25zdCBmaWVsZE5hbWUgaW4gZmllbGRzKSB7XG4gICAgICBpZiAoZXhpc3RpbmdGaWVsZE5hbWVzLmluZGV4T2YoZmllbGROYW1lKSA8IDApIHtcbiAgICAgICAgaWYgKCFmaWVsZE5hbWVJc1ZhbGlkKGZpZWxkTmFtZSwgY2xhc3NOYW1lKSkge1xuICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBjb2RlOiBQYXJzZS5FcnJvci5JTlZBTElEX0tFWV9OQU1FLFxuICAgICAgICAgICAgZXJyb3I6ICdpbnZhbGlkIGZpZWxkIG5hbWU6ICcgKyBmaWVsZE5hbWUsXG4gICAgICAgICAgfTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoIWZpZWxkTmFtZUlzVmFsaWRGb3JDbGFzcyhmaWVsZE5hbWUsIGNsYXNzTmFtZSkpIHtcbiAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgY29kZTogMTM2LFxuICAgICAgICAgICAgZXJyb3I6ICdmaWVsZCAnICsgZmllbGROYW1lICsgJyBjYW5ub3QgYmUgYWRkZWQnLFxuICAgICAgICAgIH07XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgZmllbGRUeXBlID0gZmllbGRzW2ZpZWxkTmFtZV07XG4gICAgICAgIGNvbnN0IGVycm9yID0gZmllbGRUeXBlSXNJbnZhbGlkKGZpZWxkVHlwZSk7XG4gICAgICAgIGlmIChlcnJvcikgcmV0dXJuIHsgY29kZTogZXJyb3IuY29kZSwgZXJyb3I6IGVycm9yLm1lc3NhZ2UgfTtcbiAgICAgICAgaWYgKGZpZWxkVHlwZS5kZWZhdWx0VmFsdWUgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgIGxldCBkZWZhdWx0VmFsdWVUeXBlID0gZ2V0VHlwZShmaWVsZFR5cGUuZGVmYXVsdFZhbHVlKTtcbiAgICAgICAgICBpZiAodHlwZW9mIGRlZmF1bHRWYWx1ZVR5cGUgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICBkZWZhdWx0VmFsdWVUeXBlID0geyB0eXBlOiBkZWZhdWx0VmFsdWVUeXBlIH07XG4gICAgICAgICAgfSBlbHNlIGlmICh0eXBlb2YgZGVmYXVsdFZhbHVlVHlwZSA9PT0gJ29iamVjdCcgJiYgZmllbGRUeXBlLnR5cGUgPT09ICdSZWxhdGlvbicpIHtcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgIGNvZGU6IFBhcnNlLkVycm9yLklOQ09SUkVDVF9UWVBFLFxuICAgICAgICAgICAgICBlcnJvcjogYFRoZSAnZGVmYXVsdCB2YWx1ZScgb3B0aW9uIGlzIG5vdCBhcHBsaWNhYmxlIGZvciAke3R5cGVUb1N0cmluZyhmaWVsZFR5cGUpfWAsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgIH1cbiAgICAgICAgICBpZiAoIWRiVHlwZU1hdGNoZXNPYmplY3RUeXBlKGZpZWxkVHlwZSwgZGVmYXVsdFZhbHVlVHlwZSkpIHtcbiAgICAgICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICAgIGNvZGU6IFBhcnNlLkVycm9yLklOQ09SUkVDVF9UWVBFLFxuICAgICAgICAgICAgICBlcnJvcjogYHNjaGVtYSBtaXNtYXRjaCBmb3IgJHtjbGFzc05hbWV9LiR7ZmllbGROYW1lfSBkZWZhdWx0IHZhbHVlOyBleHBlY3RlZCAke3R5cGVUb1N0cmluZyhcbiAgICAgICAgICAgICAgICBmaWVsZFR5cGVcbiAgICAgICAgICAgICAgKX0gYnV0IGdvdCAke3R5cGVUb1N0cmluZyhkZWZhdWx0VmFsdWVUeXBlKX1gLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSBpZiAoZmllbGRUeXBlLnJlcXVpcmVkKSB7XG4gICAgICAgICAgaWYgKHR5cGVvZiBmaWVsZFR5cGUgPT09ICdvYmplY3QnICYmIGZpZWxkVHlwZS50eXBlID09PSAnUmVsYXRpb24nKSB7XG4gICAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgICBjb2RlOiBQYXJzZS5FcnJvci5JTkNPUlJFQ1RfVFlQRSxcbiAgICAgICAgICAgICAgZXJyb3I6IGBUaGUgJ3JlcXVpcmVkJyBvcHRpb24gaXMgbm90IGFwcGxpY2FibGUgZm9yICR7dHlwZVRvU3RyaW5nKGZpZWxkVHlwZSl9YCxcbiAgICAgICAgICAgIH07XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgZm9yIChjb25zdCBmaWVsZE5hbWUgaW4gZGVmYXVsdENvbHVtbnNbY2xhc3NOYW1lXSkge1xuICAgICAgZmllbGRzW2ZpZWxkTmFtZV0gPSBkZWZhdWx0Q29sdW1uc1tjbGFzc05hbWVdW2ZpZWxkTmFtZV07XG4gICAgfVxuXG4gICAgY29uc3QgZ2VvUG9pbnRzID0gT2JqZWN0LmtleXMoZmllbGRzKS5maWx0ZXIoXG4gICAgICBrZXkgPT4gZmllbGRzW2tleV0gJiYgZmllbGRzW2tleV0udHlwZSA9PT0gJ0dlb1BvaW50J1xuICAgICk7XG4gICAgaWYgKGdlb1BvaW50cy5sZW5ndGggPiAxKSB7XG4gICAgICByZXR1cm4ge1xuICAgICAgICBjb2RlOiBQYXJzZS5FcnJvci5JTkNPUlJFQ1RfVFlQRSxcbiAgICAgICAgZXJyb3I6XG4gICAgICAgICAgJ2N1cnJlbnRseSwgb25seSBvbmUgR2VvUG9pbnQgZmllbGQgbWF5IGV4aXN0IGluIGFuIG9iamVjdC4gQWRkaW5nICcgK1xuICAgICAgICAgIGdlb1BvaW50c1sxXSArXG4gICAgICAgICAgJyB3aGVuICcgK1xuICAgICAgICAgIGdlb1BvaW50c1swXSArXG4gICAgICAgICAgJyBhbHJlYWR5IGV4aXN0cy4nLFxuICAgICAgfTtcbiAgICB9XG4gICAgdmFsaWRhdGVDTFAoY2xhc3NMZXZlbFBlcm1pc3Npb25zLCBmaWVsZHMsIHRoaXMudXNlcklkUmVnRXgpO1xuICB9XG5cbiAgLy8gU2V0cyB0aGUgQ2xhc3MtbGV2ZWwgcGVybWlzc2lvbnMgZm9yIGEgZ2l2ZW4gY2xhc3NOYW1lLCB3aGljaCBtdXN0IGV4aXN0LlxuICBhc3luYyBzZXRQZXJtaXNzaW9ucyhjbGFzc05hbWU6IHN0cmluZywgcGVybXM6IGFueSwgbmV3U2NoZW1hOiBTY2hlbWFGaWVsZHMpIHtcbiAgICBpZiAodHlwZW9mIHBlcm1zID09PSAndW5kZWZpbmVkJykge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgIH1cbiAgICB2YWxpZGF0ZUNMUChwZXJtcywgbmV3U2NoZW1hLCB0aGlzLnVzZXJJZFJlZ0V4KTtcbiAgICBhd2FpdCB0aGlzLl9kYkFkYXB0ZXIuc2V0Q2xhc3NMZXZlbFBlcm1pc3Npb25zKGNsYXNzTmFtZSwgcGVybXMpO1xuICAgIGNvbnN0IGNhY2hlZCA9IFNjaGVtYUNhY2hlLmdldChjbGFzc05hbWUpO1xuICAgIGlmIChjYWNoZWQpIHtcbiAgICAgIGNhY2hlZC5jbGFzc0xldmVsUGVybWlzc2lvbnMgPSBwZXJtcztcbiAgICB9XG4gIH1cblxuICAvLyBSZXR1cm5zIGEgcHJvbWlzZSB0aGF0IHJlc29sdmVzIHN1Y2Nlc3NmdWxseSB0byB0aGUgbmV3IHNjaGVtYVxuICAvLyBvYmplY3QgaWYgdGhlIHByb3ZpZGVkIGNsYXNzTmFtZS1maWVsZE5hbWUtdHlwZSB0dXBsZSBpcyB2YWxpZC5cbiAgLy8gVGhlIGNsYXNzTmFtZSBtdXN0IGFscmVhZHkgYmUgdmFsaWRhdGVkLlxuICAvLyBJZiAnZnJlZXplJyBpcyB0cnVlLCByZWZ1c2UgdG8gdXBkYXRlIHRoZSBzY2hlbWEgZm9yIHRoaXMgZmllbGQuXG4gIGVuZm9yY2VGaWVsZEV4aXN0cyhjbGFzc05hbWU6IHN0cmluZywgZmllbGROYW1lOiBzdHJpbmcsIHR5cGU6IHN0cmluZyB8IFNjaGVtYUZpZWxkKSB7XG4gICAgaWYgKGZpZWxkTmFtZS5pbmRleE9mKCcuJykgPiAwKSB7XG4gICAgICAvLyBzdWJkb2N1bWVudCBrZXkgKHgueSkgPT4gb2sgaWYgeCBpcyBvZiB0eXBlICdvYmplY3QnXG4gICAgICBmaWVsZE5hbWUgPSBmaWVsZE5hbWUuc3BsaXQoJy4nKVswXTtcbiAgICAgIHR5cGUgPSAnT2JqZWN0JztcbiAgICB9XG4gICAgaWYgKCFmaWVsZE5hbWVJc1ZhbGlkKGZpZWxkTmFtZSwgY2xhc3NOYW1lKSkge1xuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfS0VZX05BTUUsIGBJbnZhbGlkIGZpZWxkIG5hbWU6ICR7ZmllbGROYW1lfS5gKTtcbiAgICB9XG5cbiAgICAvLyBJZiBzb21lb25lIHRyaWVzIHRvIGNyZWF0ZSBhIG5ldyBmaWVsZCB3aXRoIG51bGwvdW5kZWZpbmVkIGFzIHRoZSB2YWx1ZSwgcmV0dXJuO1xuICAgIGlmICghdHlwZSkge1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICBjb25zdCBleHBlY3RlZFR5cGUgPSB0aGlzLmdldEV4cGVjdGVkVHlwZShjbGFzc05hbWUsIGZpZWxkTmFtZSk7XG4gICAgaWYgKHR5cGVvZiB0eXBlID09PSAnc3RyaW5nJykge1xuICAgICAgdHlwZSA9ICh7IHR5cGUgfTogU2NoZW1hRmllbGQpO1xuICAgIH1cblxuICAgIGlmICh0eXBlLmRlZmF1bHRWYWx1ZSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICBsZXQgZGVmYXVsdFZhbHVlVHlwZSA9IGdldFR5cGUodHlwZS5kZWZhdWx0VmFsdWUpO1xuICAgICAgaWYgKHR5cGVvZiBkZWZhdWx0VmFsdWVUeXBlID09PSAnc3RyaW5nJykge1xuICAgICAgICBkZWZhdWx0VmFsdWVUeXBlID0geyB0eXBlOiBkZWZhdWx0VmFsdWVUeXBlIH07XG4gICAgICB9XG4gICAgICBpZiAoIWRiVHlwZU1hdGNoZXNPYmplY3RUeXBlKHR5cGUsIGRlZmF1bHRWYWx1ZVR5cGUpKSB7XG4gICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICBQYXJzZS5FcnJvci5JTkNPUlJFQ1RfVFlQRSxcbiAgICAgICAgICBgc2NoZW1hIG1pc21hdGNoIGZvciAke2NsYXNzTmFtZX0uJHtmaWVsZE5hbWV9IGRlZmF1bHQgdmFsdWU7IGV4cGVjdGVkICR7dHlwZVRvU3RyaW5nKFxuICAgICAgICAgICAgdHlwZVxuICAgICAgICAgICl9IGJ1dCBnb3QgJHt0eXBlVG9TdHJpbmcoZGVmYXVsdFZhbHVlVHlwZSl9YFxuICAgICAgICApO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChleHBlY3RlZFR5cGUpIHtcbiAgICAgIGlmICghZGJUeXBlTWF0Y2hlc09iamVjdFR5cGUoZXhwZWN0ZWRUeXBlLCB0eXBlKSkge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgUGFyc2UuRXJyb3IuSU5DT1JSRUNUX1RZUEUsXG4gICAgICAgICAgYHNjaGVtYSBtaXNtYXRjaCBmb3IgJHtjbGFzc05hbWV9LiR7ZmllbGROYW1lfTsgZXhwZWN0ZWQgJHt0eXBlVG9TdHJpbmcoXG4gICAgICAgICAgICBleHBlY3RlZFR5cGVcbiAgICAgICAgICApfSBidXQgZ290ICR7dHlwZVRvU3RyaW5nKHR5cGUpfWBcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRoaXMuX2RiQWRhcHRlclxuICAgICAgLmFkZEZpZWxkSWZOb3RFeGlzdHMoY2xhc3NOYW1lLCBmaWVsZE5hbWUsIHR5cGUpXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICBpZiAoZXJyb3IuY29kZSA9PSBQYXJzZS5FcnJvci5JTkNPUlJFQ1RfVFlQRSkge1xuICAgICAgICAgIC8vIE1ha2Ugc3VyZSB0aGF0IHdlIHRocm93IGVycm9ycyB3aGVuIGl0IGlzIGFwcHJvcHJpYXRlIHRvIGRvIHNvLlxuICAgICAgICAgIHRocm93IGVycm9yO1xuICAgICAgICB9XG4gICAgICAgIC8vIFRoZSB1cGRhdGUgZmFpbGVkLiBUaGlzIGNhbiBiZSBva2F5IC0gaXQgbWlnaHQgaGF2ZSBiZWVuIGEgcmFjZVxuICAgICAgICAvLyBjb25kaXRpb24gd2hlcmUgYW5vdGhlciBjbGllbnQgdXBkYXRlZCB0aGUgc2NoZW1hIGluIHRoZSBzYW1lXG4gICAgICAgIC8vIHdheSB0aGF0IHdlIHdhbnRlZCB0by4gU28sIGp1c3QgcmVsb2FkIHRoZSBzY2hlbWFcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgICAgfSlcbiAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBjbGFzc05hbWUsXG4gICAgICAgICAgZmllbGROYW1lLFxuICAgICAgICAgIHR5cGUsXG4gICAgICAgIH07XG4gICAgICB9KTtcbiAgfVxuXG4gIGVuc3VyZUZpZWxkcyhmaWVsZHM6IGFueSkge1xuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgZmllbGRzLmxlbmd0aDsgaSArPSAxKSB7XG4gICAgICBjb25zdCB7IGNsYXNzTmFtZSwgZmllbGROYW1lIH0gPSBmaWVsZHNbaV07XG4gICAgICBsZXQgeyB0eXBlIH0gPSBmaWVsZHNbaV07XG4gICAgICBjb25zdCBleHBlY3RlZFR5cGUgPSB0aGlzLmdldEV4cGVjdGVkVHlwZShjbGFzc05hbWUsIGZpZWxkTmFtZSk7XG4gICAgICBpZiAodHlwZW9mIHR5cGUgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHR5cGUgPSB7IHR5cGU6IHR5cGUgfTtcbiAgICAgIH1cbiAgICAgIGlmICghZXhwZWN0ZWRUeXBlIHx8ICFkYlR5cGVNYXRjaGVzT2JqZWN0VHlwZShleHBlY3RlZFR5cGUsIHR5cGUpKSB7XG4gICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sIGBDb3VsZCBub3QgYWRkIGZpZWxkICR7ZmllbGROYW1lfWApO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIC8vIG1haW50YWluIGNvbXBhdGliaWxpdHlcbiAgZGVsZXRlRmllbGQoZmllbGROYW1lOiBzdHJpbmcsIGNsYXNzTmFtZTogc3RyaW5nLCBkYXRhYmFzZTogRGF0YWJhc2VDb250cm9sbGVyKSB7XG4gICAgcmV0dXJuIHRoaXMuZGVsZXRlRmllbGRzKFtmaWVsZE5hbWVdLCBjbGFzc05hbWUsIGRhdGFiYXNlKTtcbiAgfVxuXG4gIC8vIERlbGV0ZSBmaWVsZHMsIGFuZCByZW1vdmUgdGhhdCBkYXRhIGZyb20gYWxsIG9iamVjdHMuIFRoaXMgaXMgaW50ZW5kZWRcbiAgLy8gdG8gcmVtb3ZlIHVudXNlZCBmaWVsZHMsIGlmIG90aGVyIHdyaXRlcnMgYXJlIHdyaXRpbmcgb2JqZWN0cyB0aGF0IGluY2x1ZGVcbiAgLy8gdGhpcyBmaWVsZCwgdGhlIGZpZWxkIG1heSByZWFwcGVhci4gUmV0dXJucyBhIFByb21pc2UgdGhhdCByZXNvbHZlcyB3aXRoXG4gIC8vIG5vIG9iamVjdCBvbiBzdWNjZXNzLCBvciByZWplY3RzIHdpdGggeyBjb2RlLCBlcnJvciB9IG9uIGZhaWx1cmUuXG4gIC8vIFBhc3NpbmcgdGhlIGRhdGFiYXNlIGFuZCBwcmVmaXggaXMgbmVjZXNzYXJ5IGluIG9yZGVyIHRvIGRyb3AgcmVsYXRpb24gY29sbGVjdGlvbnNcbiAgLy8gYW5kIHJlbW92ZSBmaWVsZHMgZnJvbSBvYmplY3RzLiBJZGVhbGx5IHRoZSBkYXRhYmFzZSB3b3VsZCBiZWxvbmcgdG9cbiAgLy8gYSBkYXRhYmFzZSBhZGFwdGVyIGFuZCB0aGlzIGZ1bmN0aW9uIHdvdWxkIGNsb3NlIG92ZXIgaXQgb3IgYWNjZXNzIGl0IHZpYSBtZW1iZXIuXG4gIGRlbGV0ZUZpZWxkcyhmaWVsZE5hbWVzOiBBcnJheTxzdHJpbmc+LCBjbGFzc05hbWU6IHN0cmluZywgZGF0YWJhc2U6IERhdGFiYXNlQ29udHJvbGxlcikge1xuICAgIGlmICghY2xhc3NOYW1lSXNWYWxpZChjbGFzc05hbWUpKSB7XG4gICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9DTEFTU19OQU1FLCBpbnZhbGlkQ2xhc3NOYW1lTWVzc2FnZShjbGFzc05hbWUpKTtcbiAgICB9XG5cbiAgICBmaWVsZE5hbWVzLmZvckVhY2goZmllbGROYW1lID0+IHtcbiAgICAgIGlmICghZmllbGROYW1lSXNWYWxpZChmaWVsZE5hbWUsIGNsYXNzTmFtZSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfS0VZX05BTUUsIGBpbnZhbGlkIGZpZWxkIG5hbWU6ICR7ZmllbGROYW1lfWApO1xuICAgICAgfVxuICAgICAgLy9Eb24ndCBhbGxvdyBkZWxldGluZyB0aGUgZGVmYXVsdCBmaWVsZHMuXG4gICAgICBpZiAoIWZpZWxkTmFtZUlzVmFsaWRGb3JDbGFzcyhmaWVsZE5hbWUsIGNsYXNzTmFtZSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKDEzNiwgYGZpZWxkICR7ZmllbGROYW1lfSBjYW5ub3QgYmUgY2hhbmdlZGApO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgcmV0dXJuIHRoaXMuZ2V0T25lU2NoZW1hKGNsYXNzTmFtZSwgZmFsc2UsIHsgY2xlYXJDYWNoZTogdHJ1ZSB9KVxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgaWYgKGVycm9yID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0NMQVNTX05BTUUsXG4gICAgICAgICAgICBgQ2xhc3MgJHtjbGFzc05hbWV9IGRvZXMgbm90IGV4aXN0LmBcbiAgICAgICAgICApO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHRocm93IGVycm9yO1xuICAgICAgICB9XG4gICAgICB9KVxuICAgICAgLnRoZW4oc2NoZW1hID0+IHtcbiAgICAgICAgZmllbGROYW1lcy5mb3JFYWNoKGZpZWxkTmFtZSA9PiB7XG4gICAgICAgICAgaWYgKCFzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0pIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcigyNTUsIGBGaWVsZCAke2ZpZWxkTmFtZX0gZG9lcyBub3QgZXhpc3QsIGNhbm5vdCBkZWxldGUuYCk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcblxuICAgICAgICBjb25zdCBzY2hlbWFGaWVsZHMgPSB7IC4uLnNjaGVtYS5maWVsZHMgfTtcbiAgICAgICAgcmV0dXJuIGRhdGFiYXNlLmFkYXB0ZXIuZGVsZXRlRmllbGRzKGNsYXNzTmFtZSwgc2NoZW1hLCBmaWVsZE5hbWVzKS50aGVuKCgpID0+IHtcbiAgICAgICAgICByZXR1cm4gUHJvbWlzZS5hbGwoXG4gICAgICAgICAgICBmaWVsZE5hbWVzLm1hcChmaWVsZE5hbWUgPT4ge1xuICAgICAgICAgICAgICBjb25zdCBmaWVsZCA9IHNjaGVtYUZpZWxkc1tmaWVsZE5hbWVdO1xuICAgICAgICAgICAgICBpZiAoZmllbGQgJiYgZmllbGQudHlwZSA9PT0gJ1JlbGF0aW9uJykge1xuICAgICAgICAgICAgICAgIC8vRm9yIHJlbGF0aW9ucywgZHJvcCB0aGUgX0pvaW4gdGFibGVcbiAgICAgICAgICAgICAgICByZXR1cm4gZGF0YWJhc2UuYWRhcHRlci5kZWxldGVDbGFzcyhgX0pvaW46JHtmaWVsZE5hbWV9OiR7Y2xhc3NOYW1lfWApO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgICAgICAgIH0pXG4gICAgICAgICAgKTtcbiAgICAgICAgfSk7XG4gICAgICB9KVxuICAgICAgLnRoZW4oKCkgPT4ge1xuICAgICAgICBTY2hlbWFDYWNoZS5jbGVhcigpO1xuICAgICAgfSk7XG4gIH1cblxuICAvLyBWYWxpZGF0ZXMgYW4gb2JqZWN0IHByb3ZpZGVkIGluIFJFU1QgZm9ybWF0LlxuICAvLyBSZXR1cm5zIGEgcHJvbWlzZSB0aGF0IHJlc29sdmVzIHRvIHRoZSBuZXcgc2NoZW1hIGlmIHRoaXMgb2JqZWN0IGlzXG4gIC8vIHZhbGlkLlxuICBhc3luYyB2YWxpZGF0ZU9iamVjdChjbGFzc05hbWU6IHN0cmluZywgb2JqZWN0OiBhbnksIHF1ZXJ5OiBhbnkpIHtcbiAgICBsZXQgZ2VvY291bnQgPSAwO1xuICAgIGNvbnN0IHNjaGVtYSA9IGF3YWl0IHRoaXMuZW5mb3JjZUNsYXNzRXhpc3RzKGNsYXNzTmFtZSk7XG4gICAgY29uc3QgcHJvbWlzZXMgPSBbXTtcblxuICAgIGZvciAoY29uc3QgZmllbGROYW1lIGluIG9iamVjdCkge1xuICAgICAgaWYgKG9iamVjdFtmaWVsZE5hbWVdICYmIGdldFR5cGUob2JqZWN0W2ZpZWxkTmFtZV0pID09PSAnR2VvUG9pbnQnKSB7XG4gICAgICAgIGdlb2NvdW50Kys7XG4gICAgICB9XG4gICAgICBpZiAoZ2VvY291bnQgPiAxKSB7XG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChcbiAgICAgICAgICBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICBQYXJzZS5FcnJvci5JTkNPUlJFQ1RfVFlQRSxcbiAgICAgICAgICAgICd0aGVyZSBjYW4gb25seSBiZSBvbmUgZ2VvcG9pbnQgZmllbGQgaW4gYSBjbGFzcydcbiAgICAgICAgICApXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgfVxuICAgIGZvciAoY29uc3QgZmllbGROYW1lIGluIG9iamVjdCkge1xuICAgICAgaWYgKG9iamVjdFtmaWVsZE5hbWVdID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG4gICAgICBjb25zdCBleHBlY3RlZCA9IGdldFR5cGUob2JqZWN0W2ZpZWxkTmFtZV0pO1xuICAgICAgaWYgKCFleHBlY3RlZCkge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cbiAgICAgIGlmIChmaWVsZE5hbWUgPT09ICdBQ0wnKSB7XG4gICAgICAgIC8vIEV2ZXJ5IG9iamVjdCBoYXMgQUNMIGltcGxpY2l0bHkuXG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgcHJvbWlzZXMucHVzaChzY2hlbWEuZW5mb3JjZUZpZWxkRXhpc3RzKGNsYXNzTmFtZSwgZmllbGROYW1lLCBleHBlY3RlZCkpO1xuICAgIH1cbiAgICBjb25zdCByZXN1bHRzID0gYXdhaXQgUHJvbWlzZS5hbGwocHJvbWlzZXMpO1xuICAgIGNvbnN0IGVuZm9yY2VGaWVsZHMgPSByZXN1bHRzLmZpbHRlcihyZXN1bHQgPT4gISFyZXN1bHQpO1xuXG4gICAgaWYgKGVuZm9yY2VGaWVsZHMubGVuZ3RoICE9PSAwKSB7XG4gICAgICAvLyBUT0RPOiBSZW1vdmUgYnkgdXBkYXRpbmcgc2NoZW1hIGNhY2hlIGRpcmVjdGx5XG4gICAgICBhd2FpdCB0aGlzLnJlbG9hZERhdGEoeyBjbGVhckNhY2hlOiB0cnVlIH0pO1xuICAgIH1cbiAgICB0aGlzLmVuc3VyZUZpZWxkcyhlbmZvcmNlRmllbGRzKTtcblxuICAgIGNvbnN0IHByb21pc2UgPSBQcm9taXNlLnJlc29sdmUoc2NoZW1hKTtcbiAgICByZXR1cm4gdGhlblZhbGlkYXRlUmVxdWlyZWRDb2x1bW5zKHByb21pc2UsIGNsYXNzTmFtZSwgb2JqZWN0LCBxdWVyeSk7XG4gIH1cblxuICAvLyBWYWxpZGF0ZXMgdGhhdCBhbGwgdGhlIHByb3BlcnRpZXMgYXJlIHNldCBmb3IgdGhlIG9iamVjdFxuICB2YWxpZGF0ZVJlcXVpcmVkQ29sdW1ucyhjbGFzc05hbWU6IHN0cmluZywgb2JqZWN0OiBhbnksIHF1ZXJ5OiBhbnkpIHtcbiAgICBjb25zdCBjb2x1bW5zID0gcmVxdWlyZWRDb2x1bW5zW2NsYXNzTmFtZV07XG4gICAgaWYgKCFjb2x1bW5zIHx8IGNvbHVtbnMubGVuZ3RoID09IDApIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodGhpcyk7XG4gICAgfVxuXG4gICAgY29uc3QgbWlzc2luZ0NvbHVtbnMgPSBjb2x1bW5zLmZpbHRlcihmdW5jdGlvbiAoY29sdW1uKSB7XG4gICAgICBpZiAocXVlcnkgJiYgcXVlcnkub2JqZWN0SWQpIHtcbiAgICAgICAgaWYgKG9iamVjdFtjb2x1bW5dICYmIHR5cGVvZiBvYmplY3RbY29sdW1uXSA9PT0gJ29iamVjdCcpIHtcbiAgICAgICAgICAvLyBUcnlpbmcgdG8gZGVsZXRlIGEgcmVxdWlyZWQgY29sdW1uXG4gICAgICAgICAgcmV0dXJuIG9iamVjdFtjb2x1bW5dLl9fb3AgPT0gJ0RlbGV0ZSc7XG4gICAgICAgIH1cbiAgICAgICAgLy8gTm90IHRyeWluZyB0byBkbyBhbnl0aGluZyB0aGVyZVxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG4gICAgICByZXR1cm4gIW9iamVjdFtjb2x1bW5dO1xuICAgIH0pO1xuXG4gICAgaWYgKG1pc3NpbmdDb2x1bW5zLmxlbmd0aCA+IDApIHtcbiAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTkNPUlJFQ1RfVFlQRSwgbWlzc2luZ0NvbHVtbnNbMF0gKyAnIGlzIHJlcXVpcmVkLicpO1xuICAgIH1cbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKHRoaXMpO1xuICB9XG5cbiAgdGVzdFBlcm1pc3Npb25zRm9yQ2xhc3NOYW1lKGNsYXNzTmFtZTogc3RyaW5nLCBhY2xHcm91cDogc3RyaW5nW10sIG9wZXJhdGlvbjogc3RyaW5nKSB7XG4gICAgcmV0dXJuIFNjaGVtYUNvbnRyb2xsZXIudGVzdFBlcm1pc3Npb25zKFxuICAgICAgdGhpcy5nZXRDbGFzc0xldmVsUGVybWlzc2lvbnMoY2xhc3NOYW1lKSxcbiAgICAgIGFjbEdyb3VwLFxuICAgICAgb3BlcmF0aW9uXG4gICAgKTtcbiAgfVxuXG4gIC8vIFRlc3RzIHRoYXQgdGhlIGNsYXNzIGxldmVsIHBlcm1pc3Npb24gbGV0IHBhc3MgdGhlIG9wZXJhdGlvbiBmb3IgYSBnaXZlbiBhY2xHcm91cFxuICBzdGF0aWMgdGVzdFBlcm1pc3Npb25zKGNsYXNzUGVybWlzc2lvbnM6ID9hbnksIGFjbEdyb3VwOiBzdHJpbmdbXSwgb3BlcmF0aW9uOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgICBpZiAoIWNsYXNzUGVybWlzc2lvbnMgfHwgIWNsYXNzUGVybWlzc2lvbnNbb3BlcmF0aW9uXSkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGNvbnN0IHBlcm1zID0gY2xhc3NQZXJtaXNzaW9uc1tvcGVyYXRpb25dO1xuICAgIGlmIChwZXJtc1snKiddKSB7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG4gICAgLy8gQ2hlY2sgcGVybWlzc2lvbnMgYWdhaW5zdCB0aGUgYWNsR3JvdXAgcHJvdmlkZWQgKGFycmF5IG9mIHVzZXJJZC9yb2xlcylcbiAgICBpZiAoXG4gICAgICBhY2xHcm91cC5zb21lKGFjbCA9PiB7XG4gICAgICAgIHJldHVybiBwZXJtc1thY2xdID09PSB0cnVlO1xuICAgICAgfSlcbiAgICApIHtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICAvLyBWYWxpZGF0ZXMgYW4gb3BlcmF0aW9uIHBhc3NlcyBjbGFzcy1sZXZlbC1wZXJtaXNzaW9ucyBzZXQgaW4gdGhlIHNjaGVtYVxuICBzdGF0aWMgdmFsaWRhdGVQZXJtaXNzaW9uKFxuICAgIGNsYXNzUGVybWlzc2lvbnM6ID9hbnksXG4gICAgY2xhc3NOYW1lOiBzdHJpbmcsXG4gICAgYWNsR3JvdXA6IHN0cmluZ1tdLFxuICAgIG9wZXJhdGlvbjogc3RyaW5nLFxuICAgIGFjdGlvbj86IHN0cmluZ1xuICApIHtcbiAgICBpZiAoU2NoZW1hQ29udHJvbGxlci50ZXN0UGVybWlzc2lvbnMoY2xhc3NQZXJtaXNzaW9ucywgYWNsR3JvdXAsIG9wZXJhdGlvbikpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICB9XG5cbiAgICBpZiAoIWNsYXNzUGVybWlzc2lvbnMgfHwgIWNsYXNzUGVybWlzc2lvbnNbb3BlcmF0aW9uXSkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGNvbnN0IHBlcm1zID0gY2xhc3NQZXJtaXNzaW9uc1tvcGVyYXRpb25dO1xuICAgIC8vIElmIG9ubHkgZm9yIGF1dGhlbnRpY2F0ZWQgdXNlcnNcbiAgICAvLyBtYWtlIHN1cmUgd2UgaGF2ZSBhbiBhY2xHcm91cFxuICAgIGlmIChwZXJtc1sncmVxdWlyZXNBdXRoZW50aWNhdGlvbiddKSB7XG4gICAgICAvLyBJZiBhY2xHcm91cCBoYXMgKiAocHVibGljKVxuICAgICAgaWYgKCFhY2xHcm91cCB8fCBhY2xHcm91cC5sZW5ndGggPT0gMCkge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgUGFyc2UuRXJyb3IuT0JKRUNUX05PVF9GT1VORCxcbiAgICAgICAgICAnUGVybWlzc2lvbiBkZW5pZWQsIHVzZXIgbmVlZHMgdG8gYmUgYXV0aGVudGljYXRlZC4nXG4gICAgICAgICk7XG4gICAgICB9IGVsc2UgaWYgKGFjbEdyb3VwLmluZGV4T2YoJyonKSA+IC0xICYmIGFjbEdyb3VwLmxlbmd0aCA9PSAxKSB7XG4gICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICBQYXJzZS5FcnJvci5PQkpFQ1RfTk9UX0ZPVU5ELFxuICAgICAgICAgICdQZXJtaXNzaW9uIGRlbmllZCwgdXNlciBuZWVkcyB0byBiZSBhdXRoZW50aWNhdGVkLidcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIC8vIHJlcXVpcmVzQXV0aGVudGljYXRpb24gcGFzc2VkLCBqdXN0IG1vdmUgZm9yd2FyZFxuICAgICAgLy8gcHJvYmFibHkgd291bGQgYmUgd2lzZSBhdCBzb21lIHBvaW50IHRvIHJlbmFtZSB0byAnYXV0aGVudGljYXRlZFVzZXInXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgfVxuXG4gICAgLy8gTm8gbWF0Y2hpbmcgQ0xQLCBsZXQncyBjaGVjayB0aGUgUG9pbnRlciBwZXJtaXNzaW9uc1xuICAgIC8vIEFuZCBoYW5kbGUgdGhvc2UgbGF0ZXJcbiAgICBjb25zdCBwZXJtaXNzaW9uRmllbGQgPVxuICAgICAgWydnZXQnLCAnZmluZCcsICdjb3VudCddLmluZGV4T2Yob3BlcmF0aW9uKSA+IC0xID8gJ3JlYWRVc2VyRmllbGRzJyA6ICd3cml0ZVVzZXJGaWVsZHMnO1xuXG4gICAgLy8gUmVqZWN0IGNyZWF0ZSB3aGVuIHdyaXRlIGxvY2tkb3duXG4gICAgaWYgKHBlcm1pc3Npb25GaWVsZCA9PSAnd3JpdGVVc2VyRmllbGRzJyAmJiBvcGVyYXRpb24gPT0gJ2NyZWF0ZScpIHtcbiAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgUGFyc2UuRXJyb3IuT1BFUkFUSU9OX0ZPUkJJRERFTixcbiAgICAgICAgYFBlcm1pc3Npb24gZGVuaWVkIGZvciBhY3Rpb24gJHtvcGVyYXRpb259IG9uIGNsYXNzICR7Y2xhc3NOYW1lfS5gXG4gICAgICApO1xuICAgIH1cblxuICAgIC8vIFByb2Nlc3MgdGhlIHJlYWRVc2VyRmllbGRzIGxhdGVyXG4gICAgaWYgKFxuICAgICAgQXJyYXkuaXNBcnJheShjbGFzc1Blcm1pc3Npb25zW3Blcm1pc3Npb25GaWVsZF0pICYmXG4gICAgICBjbGFzc1Blcm1pc3Npb25zW3Blcm1pc3Npb25GaWVsZF0ubGVuZ3RoID4gMFxuICAgICkge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xuICAgIH1cblxuICAgIGNvbnN0IHBvaW50ZXJGaWVsZHMgPSBjbGFzc1Blcm1pc3Npb25zW29wZXJhdGlvbl0ucG9pbnRlckZpZWxkcztcbiAgICBpZiAoQXJyYXkuaXNBcnJheShwb2ludGVyRmllbGRzKSAmJiBwb2ludGVyRmllbGRzLmxlbmd0aCA+IDApIHtcbiAgICAgIC8vIGFueSBvcCBleGNlcHQgJ2FkZEZpZWxkIGFzIHBhcnQgb2YgY3JlYXRlJyBpcyBvay5cbiAgICAgIGlmIChvcGVyYXRpb24gIT09ICdhZGRGaWVsZCcgfHwgYWN0aW9uID09PSAndXBkYXRlJykge1xuICAgICAgICAvLyBXZSBjYW4gYWxsb3cgYWRkaW5nIGZpZWxkIG9uIHVwZGF0ZSBmbG93IG9ubHkuXG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICBQYXJzZS5FcnJvci5PUEVSQVRJT05fRk9SQklEREVOLFxuICAgICAgYFBlcm1pc3Npb24gZGVuaWVkIGZvciBhY3Rpb24gJHtvcGVyYXRpb259IG9uIGNsYXNzICR7Y2xhc3NOYW1lfS5gXG4gICAgKTtcbiAgfVxuXG4gIC8vIFZhbGlkYXRlcyBhbiBvcGVyYXRpb24gcGFzc2VzIGNsYXNzLWxldmVsLXBlcm1pc3Npb25zIHNldCBpbiB0aGUgc2NoZW1hXG4gIHZhbGlkYXRlUGVybWlzc2lvbihjbGFzc05hbWU6IHN0cmluZywgYWNsR3JvdXA6IHN0cmluZ1tdLCBvcGVyYXRpb246IHN0cmluZywgYWN0aW9uPzogc3RyaW5nKSB7XG4gICAgcmV0dXJuIFNjaGVtYUNvbnRyb2xsZXIudmFsaWRhdGVQZXJtaXNzaW9uKFxuICAgICAgdGhpcy5nZXRDbGFzc0xldmVsUGVybWlzc2lvbnMoY2xhc3NOYW1lKSxcbiAgICAgIGNsYXNzTmFtZSxcbiAgICAgIGFjbEdyb3VwLFxuICAgICAgb3BlcmF0aW9uLFxuICAgICAgYWN0aW9uXG4gICAgKTtcbiAgfVxuXG4gIGdldENsYXNzTGV2ZWxQZXJtaXNzaW9ucyhjbGFzc05hbWU6IHN0cmluZyk6IGFueSB7XG4gICAgcmV0dXJuIHRoaXMuc2NoZW1hRGF0YVtjbGFzc05hbWVdICYmIHRoaXMuc2NoZW1hRGF0YVtjbGFzc05hbWVdLmNsYXNzTGV2ZWxQZXJtaXNzaW9ucztcbiAgfVxuXG4gIC8vIFJldHVybnMgdGhlIGV4cGVjdGVkIHR5cGUgZm9yIGEgY2xhc3NOYW1lK2tleSBjb21iaW5hdGlvblxuICAvLyBvciB1bmRlZmluZWQgaWYgdGhlIHNjaGVtYSBpcyBub3Qgc2V0XG4gIGdldEV4cGVjdGVkVHlwZShjbGFzc05hbWU6IHN0cmluZywgZmllbGROYW1lOiBzdHJpbmcpOiA/KFNjaGVtYUZpZWxkIHwgc3RyaW5nKSB7XG4gICAgaWYgKHRoaXMuc2NoZW1hRGF0YVtjbGFzc05hbWVdKSB7XG4gICAgICBjb25zdCBleHBlY3RlZFR5cGUgPSB0aGlzLnNjaGVtYURhdGFbY2xhc3NOYW1lXS5maWVsZHNbZmllbGROYW1lXTtcbiAgICAgIHJldHVybiBleHBlY3RlZFR5cGUgPT09ICdtYXAnID8gJ09iamVjdCcgOiBleHBlY3RlZFR5cGU7XG4gICAgfVxuICAgIHJldHVybiB1bmRlZmluZWQ7XG4gIH1cblxuICAvLyBDaGVja3MgaWYgYSBnaXZlbiBjbGFzcyBpcyBpbiB0aGUgc2NoZW1hLlxuICBoYXNDbGFzcyhjbGFzc05hbWU6IHN0cmluZykge1xuICAgIGlmICh0aGlzLnNjaGVtYURhdGFbY2xhc3NOYW1lXSkge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0cnVlKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMucmVsb2FkRGF0YSgpLnRoZW4oKCkgPT4gISF0aGlzLnNjaGVtYURhdGFbY2xhc3NOYW1lXSk7XG4gIH1cbn1cblxuLy8gUmV0dXJucyBhIHByb21pc2UgZm9yIGEgbmV3IFNjaGVtYS5cbmNvbnN0IGxvYWQgPSAoZGJBZGFwdGVyOiBTdG9yYWdlQWRhcHRlciwgb3B0aW9uczogYW55KTogUHJvbWlzZTxTY2hlbWFDb250cm9sbGVyPiA9PiB7XG4gIGNvbnN0IHNjaGVtYSA9IG5ldyBTY2hlbWFDb250cm9sbGVyKGRiQWRhcHRlcik7XG4gIHJldHVybiBzY2hlbWEucmVsb2FkRGF0YShvcHRpb25zKS50aGVuKCgpID0+IHNjaGVtYSk7XG59O1xuXG4vLyBCdWlsZHMgYSBuZXcgc2NoZW1hIChpbiBzY2hlbWEgQVBJIHJlc3BvbnNlIGZvcm1hdCkgb3V0IG9mIGFuXG4vLyBleGlzdGluZyBtb25nbyBzY2hlbWEgKyBhIHNjaGVtYXMgQVBJIHB1dCByZXF1ZXN0LiBUaGlzIHJlc3BvbnNlXG4vLyBkb2VzIG5vdCBpbmNsdWRlIHRoZSBkZWZhdWx0IGZpZWxkcywgYXMgaXQgaXMgaW50ZW5kZWQgdG8gYmUgcGFzc2VkXG4vLyB0byBtb25nb1NjaGVtYUZyb21GaWVsZHNBbmRDbGFzc05hbWUuIE5vIHZhbGlkYXRpb24gaXMgZG9uZSBoZXJlLCBpdFxuLy8gaXMgZG9uZSBpbiBtb25nb1NjaGVtYUZyb21GaWVsZHNBbmRDbGFzc05hbWUuXG5mdW5jdGlvbiBidWlsZE1lcmdlZFNjaGVtYU9iamVjdChleGlzdGluZ0ZpZWxkczogU2NoZW1hRmllbGRzLCBwdXRSZXF1ZXN0OiBhbnkpOiBTY2hlbWFGaWVsZHMge1xuICBjb25zdCBuZXdTY2hlbWEgPSB7fTtcbiAgLy8gQGZsb3ctZGlzYWJsZS1uZXh0XG4gIGNvbnN0IHN5c1NjaGVtYUZpZWxkID1cbiAgICBPYmplY3Qua2V5cyhkZWZhdWx0Q29sdW1ucykuaW5kZXhPZihleGlzdGluZ0ZpZWxkcy5faWQpID09PSAtMVxuICAgICAgPyBbXVxuICAgICAgOiBPYmplY3Qua2V5cyhkZWZhdWx0Q29sdW1uc1tleGlzdGluZ0ZpZWxkcy5faWRdKTtcbiAgZm9yIChjb25zdCBvbGRGaWVsZCBpbiBleGlzdGluZ0ZpZWxkcykge1xuICAgIGlmIChcbiAgICAgIG9sZEZpZWxkICE9PSAnX2lkJyAmJlxuICAgICAgb2xkRmllbGQgIT09ICdBQ0wnICYmXG4gICAgICBvbGRGaWVsZCAhPT0gJ3VwZGF0ZWRBdCcgJiZcbiAgICAgIG9sZEZpZWxkICE9PSAnY3JlYXRlZEF0JyAmJlxuICAgICAgb2xkRmllbGQgIT09ICdvYmplY3RJZCdcbiAgICApIHtcbiAgICAgIGlmIChzeXNTY2hlbWFGaWVsZC5sZW5ndGggPiAwICYmIHN5c1NjaGVtYUZpZWxkLmluZGV4T2Yob2xkRmllbGQpICE9PSAtMSkge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IGZpZWxkSXNEZWxldGVkID0gcHV0UmVxdWVzdFtvbGRGaWVsZF0gJiYgcHV0UmVxdWVzdFtvbGRGaWVsZF0uX19vcCA9PT0gJ0RlbGV0ZSc7XG4gICAgICBpZiAoIWZpZWxkSXNEZWxldGVkKSB7XG4gICAgICAgIG5ld1NjaGVtYVtvbGRGaWVsZF0gPSBleGlzdGluZ0ZpZWxkc1tvbGRGaWVsZF07XG4gICAgICB9XG4gICAgfVxuICB9XG4gIGZvciAoY29uc3QgbmV3RmllbGQgaW4gcHV0UmVxdWVzdCkge1xuICAgIGlmIChuZXdGaWVsZCAhPT0gJ29iamVjdElkJyAmJiBwdXRSZXF1ZXN0W25ld0ZpZWxkXS5fX29wICE9PSAnRGVsZXRlJykge1xuICAgICAgaWYgKHN5c1NjaGVtYUZpZWxkLmxlbmd0aCA+IDAgJiYgc3lzU2NoZW1hRmllbGQuaW5kZXhPZihuZXdGaWVsZCkgIT09IC0xKSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgbmV3U2NoZW1hW25ld0ZpZWxkXSA9IHB1dFJlcXVlc3RbbmV3RmllbGRdO1xuICAgIH1cbiAgfVxuICByZXR1cm4gbmV3U2NoZW1hO1xufVxuXG4vLyBHaXZlbiBhIHNjaGVtYSBwcm9taXNlLCBjb25zdHJ1Y3QgYW5vdGhlciBzY2hlbWEgcHJvbWlzZSB0aGF0XG4vLyB2YWxpZGF0ZXMgdGhpcyBmaWVsZCBvbmNlIHRoZSBzY2hlbWEgbG9hZHMuXG5mdW5jdGlvbiB0aGVuVmFsaWRhdGVSZXF1aXJlZENvbHVtbnMoc2NoZW1hUHJvbWlzZSwgY2xhc3NOYW1lLCBvYmplY3QsIHF1ZXJ5KSB7XG4gIHJldHVybiBzY2hlbWFQcm9taXNlLnRoZW4oc2NoZW1hID0+IHtcbiAgICByZXR1cm4gc2NoZW1hLnZhbGlkYXRlUmVxdWlyZWRDb2x1bW5zKGNsYXNzTmFtZSwgb2JqZWN0LCBxdWVyeSk7XG4gIH0pO1xufVxuXG4vLyBHZXRzIHRoZSB0eXBlIGZyb20gYSBSRVNUIEFQSSBmb3JtYXR0ZWQgb2JqZWN0LCB3aGVyZSAndHlwZScgaXNcbi8vIGV4dGVuZGVkIHBhc3QgamF2YXNjcmlwdCB0eXBlcyB0byBpbmNsdWRlIHRoZSByZXN0IG9mIHRoZSBQYXJzZVxuLy8gdHlwZSBzeXN0ZW0uXG4vLyBUaGUgb3V0cHV0IHNob3VsZCBiZSBhIHZhbGlkIHNjaGVtYSB2YWx1ZS5cbi8vIFRPRE86IGVuc3VyZSB0aGF0IHRoaXMgaXMgY29tcGF0aWJsZSB3aXRoIHRoZSBmb3JtYXQgdXNlZCBpbiBPcGVuIERCXG5mdW5jdGlvbiBnZXRUeXBlKG9iajogYW55KTogPyhTY2hlbWFGaWVsZCB8IHN0cmluZykge1xuICBjb25zdCB0eXBlID0gdHlwZW9mIG9iajtcbiAgc3dpdGNoICh0eXBlKSB7XG4gICAgY2FzZSAnYm9vbGVhbic6XG4gICAgICByZXR1cm4gJ0Jvb2xlYW4nO1xuICAgIGNhc2UgJ3N0cmluZyc6XG4gICAgICByZXR1cm4gJ1N0cmluZyc7XG4gICAgY2FzZSAnbnVtYmVyJzpcbiAgICAgIHJldHVybiAnTnVtYmVyJztcbiAgICBjYXNlICdtYXAnOlxuICAgIGNhc2UgJ29iamVjdCc6XG4gICAgICBpZiAoIW9iaikge1xuICAgICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGdldE9iamVjdFR5cGUob2JqKTtcbiAgICBjYXNlICdmdW5jdGlvbic6XG4gICAgY2FzZSAnc3ltYm9sJzpcbiAgICBjYXNlICd1bmRlZmluZWQnOlxuICAgIGRlZmF1bHQ6XG4gICAgICB0aHJvdyAnYmFkIG9iajogJyArIG9iajtcbiAgfVxufVxuXG4vLyBUaGlzIGdldHMgdGhlIHR5cGUgZm9yIG5vbi1KU09OIHR5cGVzIGxpa2UgcG9pbnRlcnMgYW5kIGZpbGVzLCBidXRcbi8vIGFsc28gZ2V0cyB0aGUgYXBwcm9wcmlhdGUgdHlwZSBmb3IgJCBvcGVyYXRvcnMuXG4vLyBSZXR1cm5zIG51bGwgaWYgdGhlIHR5cGUgaXMgdW5rbm93bi5cbmZ1bmN0aW9uIGdldE9iamVjdFR5cGUob2JqKTogPyhTY2hlbWFGaWVsZCB8IHN0cmluZykge1xuICBpZiAob2JqIGluc3RhbmNlb2YgQXJyYXkpIHtcbiAgICByZXR1cm4gJ0FycmF5JztcbiAgfVxuICBpZiAob2JqLl9fdHlwZSkge1xuICAgIHN3aXRjaCAob2JqLl9fdHlwZSkge1xuICAgICAgY2FzZSAnUG9pbnRlcic6XG4gICAgICAgIGlmIChvYmouY2xhc3NOYW1lKSB7XG4gICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIHR5cGU6ICdQb2ludGVyJyxcbiAgICAgICAgICAgIHRhcmdldENsYXNzOiBvYmouY2xhc3NOYW1lLFxuICAgICAgICAgIH07XG4gICAgICAgIH1cbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICdSZWxhdGlvbic6XG4gICAgICAgIGlmIChvYmouY2xhc3NOYW1lKSB7XG4gICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIHR5cGU6ICdSZWxhdGlvbicsXG4gICAgICAgICAgICB0YXJnZXRDbGFzczogb2JqLmNsYXNzTmFtZSxcbiAgICAgICAgICB9O1xuICAgICAgICB9XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAnRmlsZSc6XG4gICAgICAgIGlmIChvYmoubmFtZSkge1xuICAgICAgICAgIHJldHVybiAnRmlsZSc7XG4gICAgICAgIH1cbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICdEYXRlJzpcbiAgICAgICAgaWYgKG9iai5pc28pIHtcbiAgICAgICAgICByZXR1cm4gJ0RhdGUnO1xuICAgICAgICB9XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAnR2VvUG9pbnQnOlxuICAgICAgICBpZiAob2JqLmxhdGl0dWRlICE9IG51bGwgJiYgb2JqLmxvbmdpdHVkZSAhPSBudWxsKSB7XG4gICAgICAgICAgcmV0dXJuICdHZW9Qb2ludCc7XG4gICAgICAgIH1cbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICdCeXRlcyc6XG4gICAgICAgIGlmIChvYmouYmFzZTY0KSB7XG4gICAgICAgICAgcmV0dXJuICdCeXRlcyc7XG4gICAgICAgIH1cbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICdQb2x5Z29uJzpcbiAgICAgICAgaWYgKG9iai5jb29yZGluYXRlcykge1xuICAgICAgICAgIHJldHVybiAnUG9seWdvbic7XG4gICAgICAgIH1cbiAgICAgICAgYnJlYWs7XG4gICAgfVxuICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTkNPUlJFQ1RfVFlQRSwgJ1RoaXMgaXMgbm90IGEgdmFsaWQgJyArIG9iai5fX3R5cGUpO1xuICB9XG4gIGlmIChvYmpbJyRuZSddKSB7XG4gICAgcmV0dXJuIGdldE9iamVjdFR5cGUob2JqWyckbmUnXSk7XG4gIH1cbiAgaWYgKG9iai5fX29wKSB7XG4gICAgc3dpdGNoIChvYmouX19vcCkge1xuICAgICAgY2FzZSAnSW5jcmVtZW50JzpcbiAgICAgICAgcmV0dXJuICdOdW1iZXInO1xuICAgICAgY2FzZSAnRGVsZXRlJzpcbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICBjYXNlICdBZGQnOlxuICAgICAgY2FzZSAnQWRkVW5pcXVlJzpcbiAgICAgIGNhc2UgJ1JlbW92ZSc6XG4gICAgICAgIHJldHVybiAnQXJyYXknO1xuICAgICAgY2FzZSAnQWRkUmVsYXRpb24nOlxuICAgICAgY2FzZSAnUmVtb3ZlUmVsYXRpb24nOlxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHR5cGU6ICdSZWxhdGlvbicsXG4gICAgICAgICAgdGFyZ2V0Q2xhc3M6IG9iai5vYmplY3RzWzBdLmNsYXNzTmFtZSxcbiAgICAgICAgfTtcbiAgICAgIGNhc2UgJ0JhdGNoJzpcbiAgICAgICAgcmV0dXJuIGdldE9iamVjdFR5cGUob2JqLm9wc1swXSk7XG4gICAgICBkZWZhdWx0OlxuICAgICAgICB0aHJvdyAndW5leHBlY3RlZCBvcDogJyArIG9iai5fX29wO1xuICAgIH1cbiAgfVxuICByZXR1cm4gJ09iamVjdCc7XG59XG5cbmV4cG9ydCB7XG4gIGxvYWQsXG4gIGNsYXNzTmFtZUlzVmFsaWQsXG4gIGZpZWxkTmFtZUlzVmFsaWQsXG4gIGludmFsaWRDbGFzc05hbWVNZXNzYWdlLFxuICBidWlsZE1lcmdlZFNjaGVtYU9iamVjdCxcbiAgc3lzdGVtQ2xhc3NlcyxcbiAgZGVmYXVsdENvbHVtbnMsXG4gIGNvbnZlcnRTY2hlbWFUb0FkYXB0ZXJTY2hlbWEsXG4gIFZvbGF0aWxlQ2xhc3Nlc1NjaGVtYXMsXG4gIFNjaGVtYUNvbnRyb2xsZXIsXG59O1xuIl19