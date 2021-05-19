"use strict";

var _logger = _interopRequireDefault(require("../../../logger"));

var _lodash = _interopRequireDefault(require("lodash"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var mongodb = require('mongodb');

var Parse = require('parse/node').Parse;

const transformKey = (className, fieldName, schema) => {
  // Check if the schema is known since it's a built-in field.
  switch (fieldName) {
    case 'objectId':
      return '_id';

    case 'createdAt':
      return '_created_at';

    case 'updatedAt':
      return '_updated_at';

    case 'sessionToken':
      return '_session_token';

    case 'lastUsed':
      return '_last_used';

    case 'timesUsed':
      return 'times_used';
  }

  if (schema.fields[fieldName] && schema.fields[fieldName].__type == 'Pointer') {
    fieldName = '_p_' + fieldName;
  } else if (schema.fields[fieldName] && schema.fields[fieldName].type == 'Pointer') {
    fieldName = '_p_' + fieldName;
  }

  return fieldName;
};

const transformKeyValueForUpdate = (className, restKey, restValue, parseFormatSchema) => {
  // Check if the schema is known since it's a built-in field.
  var key = restKey;
  var timeField = false;

  switch (key) {
    case 'objectId':
    case '_id':
      if (['_GlobalConfig', '_GraphQLConfig'].includes(className)) {
        return {
          key: key,
          value: parseInt(restValue)
        };
      }

      key = '_id';
      break;

    case 'createdAt':
    case '_created_at':
      key = '_created_at';
      timeField = true;
      break;

    case 'updatedAt':
    case '_updated_at':
      key = '_updated_at';
      timeField = true;
      break;

    case 'sessionToken':
    case '_session_token':
      key = '_session_token';
      break;

    case 'expiresAt':
    case '_expiresAt':
      key = 'expiresAt';
      timeField = true;
      break;

    case '_email_verify_token_expires_at':
      key = '_email_verify_token_expires_at';
      timeField = true;
      break;

    case '_account_lockout_expires_at':
      key = '_account_lockout_expires_at';
      timeField = true;
      break;

    case '_failed_login_count':
      key = '_failed_login_count';
      break;

    case '_perishable_token_expires_at':
      key = '_perishable_token_expires_at';
      timeField = true;
      break;

    case '_password_changed_at':
      key = '_password_changed_at';
      timeField = true;
      break;

    case '_rperm':
    case '_wperm':
      return {
        key: key,
        value: restValue
      };

    case 'lastUsed':
    case '_last_used':
      key = '_last_used';
      timeField = true;
      break;

    case 'timesUsed':
    case 'times_used':
      key = 'times_used';
      timeField = true;
      break;
  }

  if (parseFormatSchema.fields[key] && parseFormatSchema.fields[key].type === 'Pointer' || !key.includes('.') && !parseFormatSchema.fields[key] && restValue && restValue.__type == 'Pointer' // Do not use the _p_ prefix for pointers inside nested documents
  ) {
      key = '_p_' + key;
    } // Handle atomic values


  var value = transformTopLevelAtom(restValue);

  if (value !== CannotTransform) {
    if (timeField && typeof value === 'string') {
      value = new Date(value);
    }

    if (restKey.indexOf('.') > 0) {
      return {
        key,
        value: restValue
      };
    }

    return {
      key,
      value
    };
  } // Handle arrays


  if (restValue instanceof Array) {
    value = restValue.map(transformInteriorValue);
    return {
      key,
      value
    };
  } // Handle update operators


  if (typeof restValue === 'object' && '__op' in restValue) {
    return {
      key,
      value: transformUpdateOperator(restValue, false)
    };
  } // Handle normal objects by recursing


  value = mapValues(restValue, transformInteriorValue);
  return {
    key,
    value
  };
};

const isRegex = value => {
  return value && value instanceof RegExp;
};

const isStartsWithRegex = value => {
  if (!isRegex(value)) {
    return false;
  }

  const matches = value.toString().match(/\/\^\\Q.*\\E\//);
  return !!matches;
};

const isAllValuesRegexOrNone = values => {
  if (!values || !Array.isArray(values) || values.length === 0) {
    return true;
  }

  const firstValuesIsRegex = isStartsWithRegex(values[0]);

  if (values.length === 1) {
    return firstValuesIsRegex;
  }

  for (let i = 1, length = values.length; i < length; ++i) {
    if (firstValuesIsRegex !== isStartsWithRegex(values[i])) {
      return false;
    }
  }

  return true;
};

const isAnyValueRegex = values => {
  return values.some(function (value) {
    return isRegex(value);
  });
};

const transformInteriorValue = restValue => {
  if (restValue !== null && typeof restValue === 'object' && Object.keys(restValue).some(key => key.includes('$') || key.includes('.'))) {
    throw new Parse.Error(Parse.Error.INVALID_NESTED_KEY, "Nested keys should not contain the '$' or '.' characters");
  } // Handle atomic values


  var value = transformInteriorAtom(restValue);

  if (value !== CannotTransform) {
    return value;
  } // Handle arrays


  if (restValue instanceof Array) {
    return restValue.map(transformInteriorValue);
  } // Handle update operators


  if (typeof restValue === 'object' && '__op' in restValue) {
    return transformUpdateOperator(restValue, true);
  } // Handle normal objects by recursing


  return mapValues(restValue, transformInteriorValue);
};

const valueAsDate = value => {
  if (typeof value === 'string') {
    return new Date(value);
  } else if (value instanceof Date) {
    return value;
  }

  return false;
};

function transformQueryKeyValue(className, key, value, schema, count = false) {
  switch (key) {
    case 'createdAt':
      if (valueAsDate(value)) {
        return {
          key: '_created_at',
          value: valueAsDate(value)
        };
      }

      key = '_created_at';
      break;

    case 'updatedAt':
      if (valueAsDate(value)) {
        return {
          key: '_updated_at',
          value: valueAsDate(value)
        };
      }

      key = '_updated_at';
      break;

    case 'expiresAt':
      if (valueAsDate(value)) {
        return {
          key: 'expiresAt',
          value: valueAsDate(value)
        };
      }

      break;

    case '_email_verify_token_expires_at':
      if (valueAsDate(value)) {
        return {
          key: '_email_verify_token_expires_at',
          value: valueAsDate(value)
        };
      }

      break;

    case 'objectId':
      {
        if (['_GlobalConfig', '_GraphQLConfig'].includes(className)) {
          value = parseInt(value);
        }

        return {
          key: '_id',
          value
        };
      }

    case '_account_lockout_expires_at':
      if (valueAsDate(value)) {
        return {
          key: '_account_lockout_expires_at',
          value: valueAsDate(value)
        };
      }

      break;

    case '_failed_login_count':
      return {
        key,
        value
      };

    case 'sessionToken':
      return {
        key: '_session_token',
        value
      };

    case '_perishable_token_expires_at':
      if (valueAsDate(value)) {
        return {
          key: '_perishable_token_expires_at',
          value: valueAsDate(value)
        };
      }

      break;

    case '_password_changed_at':
      if (valueAsDate(value)) {
        return {
          key: '_password_changed_at',
          value: valueAsDate(value)
        };
      }

      break;

    case '_rperm':
    case '_wperm':
    case '_perishable_token':
    case '_email_verify_token':
      return {
        key,
        value
      };

    case '$or':
    case '$and':
    case '$nor':
      return {
        key: key,
        value: value.map(subQuery => transformWhere(className, subQuery, schema, count))
      };

    case 'lastUsed':
      if (valueAsDate(value)) {
        return {
          key: '_last_used',
          value: valueAsDate(value)
        };
      }

      key = '_last_used';
      break;

    case 'timesUsed':
      return {
        key: 'times_used',
        value: value
      };

    default:
      {
        // Other auth data
        const authDataMatch = key.match(/^authData\.([a-zA-Z0-9_]+)\.id$/);

        if (authDataMatch) {
          const provider = authDataMatch[1]; // Special-case auth data.

          return {
            key: `_auth_data_${provider}.id`,
            value
          };
        }
      }
  }

  const expectedTypeIsArray = schema && schema.fields[key] && schema.fields[key].type === 'Array';
  const expectedTypeIsPointer = schema && schema.fields[key] && schema.fields[key].type === 'Pointer';
  const field = schema && schema.fields[key];

  if (expectedTypeIsPointer || !schema && !key.includes('.') && value && value.__type === 'Pointer') {
    key = '_p_' + key;
  } // Handle query constraints


  const transformedConstraint = transformConstraint(value, field, count);

  if (transformedConstraint !== CannotTransform) {
    if (transformedConstraint.$text) {
      return {
        key: '$text',
        value: transformedConstraint.$text
      };
    }

    if (transformedConstraint.$elemMatch) {
      return {
        key: '$nor',
        value: [{
          [key]: transformedConstraint
        }]
      };
    }

    return {
      key,
      value: transformedConstraint
    };
  }

  if (expectedTypeIsArray && !(value instanceof Array)) {
    return {
      key,
      value: {
        $all: [transformInteriorAtom(value)]
      }
    };
  } // Handle atomic values


  var transformRes = key.includes('.') ? transformInteriorAtom(value) : transformTopLevelAtom(value);

  if (transformRes !== CannotTransform) {
    return {
      key,
      value: transformRes
    };
  } else {
    throw new Parse.Error(Parse.Error.INVALID_JSON, `You cannot use ${value} as a query parameter.`);
  }
} // Main exposed method to help run queries.
// restWhere is the "where" clause in REST API form.
// Returns the mongo form of the query.


function transformWhere(className, restWhere, schema, count = false) {
  const mongoWhere = {};

  for (const restKey in restWhere) {
    const out = transformQueryKeyValue(className, restKey, restWhere[restKey], schema, count);
    mongoWhere[out.key] = out.value;
  }

  return mongoWhere;
}

const parseObjectKeyValueToMongoObjectKeyValue = (restKey, restValue, schema) => {
  // Check if the schema is known since it's a built-in field.
  let transformedValue;
  let coercedToDate;

  switch (restKey) {
    case 'objectId':
      return {
        key: '_id',
        value: restValue
      };

    case 'expiresAt':
      transformedValue = transformTopLevelAtom(restValue);
      coercedToDate = typeof transformedValue === 'string' ? new Date(transformedValue) : transformedValue;
      return {
        key: 'expiresAt',
        value: coercedToDate
      };

    case '_email_verify_token_expires_at':
      transformedValue = transformTopLevelAtom(restValue);
      coercedToDate = typeof transformedValue === 'string' ? new Date(transformedValue) : transformedValue;
      return {
        key: '_email_verify_token_expires_at',
        value: coercedToDate
      };

    case '_account_lockout_expires_at':
      transformedValue = transformTopLevelAtom(restValue);
      coercedToDate = typeof transformedValue === 'string' ? new Date(transformedValue) : transformedValue;
      return {
        key: '_account_lockout_expires_at',
        value: coercedToDate
      };

    case '_perishable_token_expires_at':
      transformedValue = transformTopLevelAtom(restValue);
      coercedToDate = typeof transformedValue === 'string' ? new Date(transformedValue) : transformedValue;
      return {
        key: '_perishable_token_expires_at',
        value: coercedToDate
      };

    case '_password_changed_at':
      transformedValue = transformTopLevelAtom(restValue);
      coercedToDate = typeof transformedValue === 'string' ? new Date(transformedValue) : transformedValue;
      return {
        key: '_password_changed_at',
        value: coercedToDate
      };

    case '_failed_login_count':
    case '_rperm':
    case '_wperm':
    case '_email_verify_token':
    case '_hashed_password':
    case '_perishable_token':
      return {
        key: restKey,
        value: restValue
      };

    case 'sessionToken':
      return {
        key: '_session_token',
        value: restValue
      };

    default:
      // Auth data should have been transformed already
      if (restKey.match(/^authData\.([a-zA-Z0-9_]+)\.id$/)) {
        throw new Parse.Error(Parse.Error.INVALID_KEY_NAME, 'can only query on ' + restKey);
      } // Trust that the auth data has been transformed and save it directly


      if (restKey.match(/^_auth_data_[a-zA-Z0-9_]+$/)) {
        return {
          key: restKey,
          value: restValue
        };
      }

  } //skip straight to transformTopLevelAtom for Bytes, they don't show up in the schema for some reason


  if (restValue && restValue.__type !== 'Bytes') {
    //Note: We may not know the type of a field here, as the user could be saving (null) to a field
    //That never existed before, meaning we can't infer the type.
    if (schema.fields[restKey] && schema.fields[restKey].type == 'Pointer' || restValue.__type == 'Pointer') {
      restKey = '_p_' + restKey;
    }
  } // Handle atomic values


  var value = transformTopLevelAtom(restValue);

  if (value !== CannotTransform) {
    return {
      key: restKey,
      value: value
    };
  } // ACLs are handled before this method is called
  // If an ACL key still exists here, something is wrong.


  if (restKey === 'ACL') {
    throw 'There was a problem transforming an ACL.';
  } // Handle arrays


  if (restValue instanceof Array) {
    value = restValue.map(transformInteriorValue);
    return {
      key: restKey,
      value: value
    };
  } // Handle normal objects by recursing


  if (Object.keys(restValue).some(key => key.includes('$') || key.includes('.'))) {
    throw new Parse.Error(Parse.Error.INVALID_NESTED_KEY, "Nested keys should not contain the '$' or '.' characters");
  }

  value = mapValues(restValue, transformInteriorValue);
  return {
    key: restKey,
    value
  };
};

const parseObjectToMongoObjectForCreate = (className, restCreate, schema) => {
  restCreate = addLegacyACL(restCreate);
  const mongoCreate = {};

  for (const restKey in restCreate) {
    if (restCreate[restKey] && restCreate[restKey].__type === 'Relation') {
      continue;
    }

    const {
      key,
      value
    } = parseObjectKeyValueToMongoObjectKeyValue(restKey, restCreate[restKey], schema);

    if (value !== undefined) {
      mongoCreate[key] = value;
    }
  } // Use the legacy mongo format for createdAt and updatedAt


  if (mongoCreate.createdAt) {
    mongoCreate._created_at = new Date(mongoCreate.createdAt.iso || mongoCreate.createdAt);
    delete mongoCreate.createdAt;
  }

  if (mongoCreate.updatedAt) {
    mongoCreate._updated_at = new Date(mongoCreate.updatedAt.iso || mongoCreate.updatedAt);
    delete mongoCreate.updatedAt;
  }

  return mongoCreate;
}; // Main exposed method to help update old objects.


const transformUpdate = (className, restUpdate, parseFormatSchema) => {
  const mongoUpdate = {};
  const acl = addLegacyACL(restUpdate);

  if (acl._rperm || acl._wperm || acl._acl) {
    mongoUpdate.$set = {};

    if (acl._rperm) {
      mongoUpdate.$set._rperm = acl._rperm;
    }

    if (acl._wperm) {
      mongoUpdate.$set._wperm = acl._wperm;
    }

    if (acl._acl) {
      mongoUpdate.$set._acl = acl._acl;
    }
  }

  for (var restKey in restUpdate) {
    if (restUpdate[restKey] && restUpdate[restKey].__type === 'Relation') {
      continue;
    }

    var out = transformKeyValueForUpdate(className, restKey, restUpdate[restKey], parseFormatSchema); // If the output value is an object with any $ keys, it's an
    // operator that needs to be lifted onto the top level update
    // object.

    if (typeof out.value === 'object' && out.value !== null && out.value.__op) {
      mongoUpdate[out.value.__op] = mongoUpdate[out.value.__op] || {};
      mongoUpdate[out.value.__op][out.key] = out.value.arg;
    } else {
      mongoUpdate['$set'] = mongoUpdate['$set'] || {};
      mongoUpdate['$set'][out.key] = out.value;
    }
  }

  return mongoUpdate;
}; // Add the legacy _acl format.


const addLegacyACL = restObject => {
  const restObjectCopy = _objectSpread({}, restObject);

  const _acl = {};

  if (restObject._wperm) {
    restObject._wperm.forEach(entry => {
      _acl[entry] = {
        w: true
      };
    });

    restObjectCopy._acl = _acl;
  }

  if (restObject._rperm) {
    restObject._rperm.forEach(entry => {
      if (!(entry in _acl)) {
        _acl[entry] = {
          r: true
        };
      } else {
        _acl[entry].r = true;
      }
    });

    restObjectCopy._acl = _acl;
  }

  return restObjectCopy;
}; // A sentinel value that helper transformations return when they
// cannot perform a transformation


function CannotTransform() {}

const transformInteriorAtom = atom => {
  // TODO: check validity harder for the __type-defined types
  if (typeof atom === 'object' && atom && !(atom instanceof Date) && atom.__type === 'Pointer') {
    return {
      __type: 'Pointer',
      className: atom.className,
      objectId: atom.objectId
    };
  } else if (typeof atom === 'function' || typeof atom === 'symbol') {
    throw new Parse.Error(Parse.Error.INVALID_JSON, `cannot transform value: ${atom}`);
  } else if (DateCoder.isValidJSON(atom)) {
    return DateCoder.JSONToDatabase(atom);
  } else if (BytesCoder.isValidJSON(atom)) {
    return BytesCoder.JSONToDatabase(atom);
  } else if (typeof atom === 'object' && atom && atom.$regex !== undefined) {
    return new RegExp(atom.$regex);
  } else {
    return atom;
  }
}; // Helper function to transform an atom from REST format to Mongo format.
// An atom is anything that can't contain other expressions. So it
// includes things where objects are used to represent other
// datatypes, like pointers and dates, but it does not include objects
// or arrays with generic stuff inside.
// Raises an error if this cannot possibly be valid REST format.
// Returns CannotTransform if it's just not an atom


function transformTopLevelAtom(atom, field) {
  switch (typeof atom) {
    case 'number':
    case 'boolean':
    case 'undefined':
      return atom;

    case 'string':
      if (field && field.type === 'Pointer') {
        return `${field.targetClass}$${atom}`;
      }

      return atom;

    case 'symbol':
    case 'function':
      throw new Parse.Error(Parse.Error.INVALID_JSON, `cannot transform value: ${atom}`);

    case 'object':
      if (atom instanceof Date) {
        // Technically dates are not rest format, but, it seems pretty
        // clear what they should be transformed to, so let's just do it.
        return atom;
      }

      if (atom === null) {
        return atom;
      } // TODO: check validity harder for the __type-defined types


      if (atom.__type == 'Pointer') {
        return `${atom.className}$${atom.objectId}`;
      }

      if (DateCoder.isValidJSON(atom)) {
        return DateCoder.JSONToDatabase(atom);
      }

      if (BytesCoder.isValidJSON(atom)) {
        return BytesCoder.JSONToDatabase(atom);
      }

      if (GeoPointCoder.isValidJSON(atom)) {
        return GeoPointCoder.JSONToDatabase(atom);
      }

      if (PolygonCoder.isValidJSON(atom)) {
        return PolygonCoder.JSONToDatabase(atom);
      }

      if (FileCoder.isValidJSON(atom)) {
        return FileCoder.JSONToDatabase(atom);
      }

      return CannotTransform;

    default:
      // I don't think typeof can ever let us get here
      throw new Parse.Error(Parse.Error.INTERNAL_SERVER_ERROR, `really did not expect value: ${atom}`);
  }
}

function relativeTimeToDate(text, now = new Date()) {
  text = text.toLowerCase();
  let parts = text.split(' '); // Filter out whitespace

  parts = parts.filter(part => part !== '');
  const future = parts[0] === 'in';
  const past = parts[parts.length - 1] === 'ago';

  if (!future && !past && text !== 'now') {
    return {
      status: 'error',
      info: "Time should either start with 'in' or end with 'ago'"
    };
  }

  if (future && past) {
    return {
      status: 'error',
      info: "Time cannot have both 'in' and 'ago'"
    };
  } // strip the 'ago' or 'in'


  if (future) {
    parts = parts.slice(1);
  } else {
    // past
    parts = parts.slice(0, parts.length - 1);
  }

  if (parts.length % 2 !== 0 && text !== 'now') {
    return {
      status: 'error',
      info: 'Invalid time string. Dangling unit or number.'
    };
  }

  const pairs = [];

  while (parts.length) {
    pairs.push([parts.shift(), parts.shift()]);
  }

  let seconds = 0;

  for (const [num, interval] of pairs) {
    const val = Number(num);

    if (!Number.isInteger(val)) {
      return {
        status: 'error',
        info: `'${num}' is not an integer.`
      };
    }

    switch (interval) {
      case 'yr':
      case 'yrs':
      case 'year':
      case 'years':
        seconds += val * 31536000; // 365 * 24 * 60 * 60

        break;

      case 'wk':
      case 'wks':
      case 'week':
      case 'weeks':
        seconds += val * 604800; // 7 * 24 * 60 * 60

        break;

      case 'd':
      case 'day':
      case 'days':
        seconds += val * 86400; // 24 * 60 * 60

        break;

      case 'hr':
      case 'hrs':
      case 'hour':
      case 'hours':
        seconds += val * 3600; // 60 * 60

        break;

      case 'min':
      case 'mins':
      case 'minute':
      case 'minutes':
        seconds += val * 60;
        break;

      case 'sec':
      case 'secs':
      case 'second':
      case 'seconds':
        seconds += val;
        break;

      default:
        return {
          status: 'error',
          info: `Invalid interval: '${interval}'`
        };
    }
  }

  const milliseconds = seconds * 1000;

  if (future) {
    return {
      status: 'success',
      info: 'future',
      result: new Date(now.valueOf() + milliseconds)
    };
  } else if (past) {
    return {
      status: 'success',
      info: 'past',
      result: new Date(now.valueOf() - milliseconds)
    };
  } else {
    return {
      status: 'success',
      info: 'present',
      result: new Date(now.valueOf())
    };
  }
} // Transforms a query constraint from REST API format to Mongo format.
// A constraint is something with fields like $lt.
// If it is not a valid constraint but it could be a valid something
// else, return CannotTransform.
// inArray is whether this is an array field.


function transformConstraint(constraint, field, count = false) {
  const inArray = field && field.type && field.type === 'Array';

  if (typeof constraint !== 'object' || !constraint) {
    return CannotTransform;
  }

  const transformFunction = inArray ? transformInteriorAtom : transformTopLevelAtom;

  const transformer = atom => {
    const result = transformFunction(atom, field);

    if (result === CannotTransform) {
      throw new Parse.Error(Parse.Error.INVALID_JSON, `bad atom: ${JSON.stringify(atom)}`);
    }

    return result;
  }; // keys is the constraints in reverse alphabetical order.
  // This is a hack so that:
  //   $regex is handled before $options
  //   $nearSphere is handled before $maxDistance


  var keys = Object.keys(constraint).sort().reverse();
  var answer = {};

  for (var key of keys) {
    switch (key) {
      case '$lt':
      case '$lte':
      case '$gt':
      case '$gte':
      case '$exists':
      case '$ne':
      case '$eq':
        {
          const val = constraint[key];

          if (val && typeof val === 'object' && val.$relativeTime) {
            if (field && field.type !== 'Date') {
              throw new Parse.Error(Parse.Error.INVALID_JSON, '$relativeTime can only be used with Date field');
            }

            switch (key) {
              case '$exists':
              case '$ne':
              case '$eq':
                throw new Parse.Error(Parse.Error.INVALID_JSON, '$relativeTime can only be used with the $lt, $lte, $gt, and $gte operators');
            }

            const parserResult = relativeTimeToDate(val.$relativeTime);

            if (parserResult.status === 'success') {
              answer[key] = parserResult.result;
              break;
            }

            _logger.default.info('Error while parsing relative date', parserResult);

            throw new Parse.Error(Parse.Error.INVALID_JSON, `bad $relativeTime (${key}) value. ${parserResult.info}`);
          }

          answer[key] = transformer(val);
          break;
        }

      case '$in':
      case '$nin':
        {
          const arr = constraint[key];

          if (!(arr instanceof Array)) {
            throw new Parse.Error(Parse.Error.INVALID_JSON, 'bad ' + key + ' value');
          }

          answer[key] = _lodash.default.flatMap(arr, value => {
            return (atom => {
              if (Array.isArray(atom)) {
                return value.map(transformer);
              } else {
                return transformer(atom);
              }
            })(value);
          });
          break;
        }

      case '$all':
        {
          const arr = constraint[key];

          if (!(arr instanceof Array)) {
            throw new Parse.Error(Parse.Error.INVALID_JSON, 'bad ' + key + ' value');
          }

          answer[key] = arr.map(transformInteriorAtom);
          const values = answer[key];

          if (isAnyValueRegex(values) && !isAllValuesRegexOrNone(values)) {
            throw new Parse.Error(Parse.Error.INVALID_JSON, 'All $all values must be of regex type or none: ' + values);
          }

          break;
        }

      case '$regex':
        var s = constraint[key];

        if (typeof s !== 'string') {
          throw new Parse.Error(Parse.Error.INVALID_JSON, 'bad regex: ' + s);
        }

        answer[key] = s;
        break;

      case '$containedBy':
        {
          const arr = constraint[key];

          if (!(arr instanceof Array)) {
            throw new Parse.Error(Parse.Error.INVALID_JSON, `bad $containedBy: should be an array`);
          }

          answer.$elemMatch = {
            $nin: arr.map(transformer)
          };
          break;
        }

      case '$options':
        answer[key] = constraint[key];
        break;

      case '$text':
        {
          const search = constraint[key].$search;

          if (typeof search !== 'object') {
            throw new Parse.Error(Parse.Error.INVALID_JSON, `bad $text: $search, should be object`);
          }

          if (!search.$term || typeof search.$term !== 'string') {
            throw new Parse.Error(Parse.Error.INVALID_JSON, `bad $text: $term, should be string`);
          } else {
            answer[key] = {
              $search: search.$term
            };
          }

          if (search.$language && typeof search.$language !== 'string') {
            throw new Parse.Error(Parse.Error.INVALID_JSON, `bad $text: $language, should be string`);
          } else if (search.$language) {
            answer[key].$language = search.$language;
          }

          if (search.$caseSensitive && typeof search.$caseSensitive !== 'boolean') {
            throw new Parse.Error(Parse.Error.INVALID_JSON, `bad $text: $caseSensitive, should be boolean`);
          } else if (search.$caseSensitive) {
            answer[key].$caseSensitive = search.$caseSensitive;
          }

          if (search.$diacriticSensitive && typeof search.$diacriticSensitive !== 'boolean') {
            throw new Parse.Error(Parse.Error.INVALID_JSON, `bad $text: $diacriticSensitive, should be boolean`);
          } else if (search.$diacriticSensitive) {
            answer[key].$diacriticSensitive = search.$diacriticSensitive;
          }

          break;
        }

      case '$nearSphere':
        {
          const point = constraint[key];

          if (count) {
            answer.$geoWithin = {
              $centerSphere: [[point.longitude, point.latitude], constraint.$maxDistance]
            };
          } else {
            answer[key] = [point.longitude, point.latitude];
          }

          break;
        }

      case '$maxDistance':
        {
          if (count) {
            break;
          }

          answer[key] = constraint[key];
          break;
        }
      // The SDKs don't seem to use these but they are documented in the
      // REST API docs.

      case '$maxDistanceInRadians':
        answer['$maxDistance'] = constraint[key];
        break;

      case '$maxDistanceInMiles':
        answer['$maxDistance'] = constraint[key] / 3959;
        break;

      case '$maxDistanceInKilometers':
        answer['$maxDistance'] = constraint[key] / 6371;
        break;

      case '$select':
      case '$dontSelect':
        throw new Parse.Error(Parse.Error.COMMAND_UNAVAILABLE, 'the ' + key + ' constraint is not supported yet');

      case '$within':
        var box = constraint[key]['$box'];

        if (!box || box.length != 2) {
          throw new Parse.Error(Parse.Error.INVALID_JSON, 'malformatted $within arg');
        }

        answer[key] = {
          $box: [[box[0].longitude, box[0].latitude], [box[1].longitude, box[1].latitude]]
        };
        break;

      case '$geoWithin':
        {
          const polygon = constraint[key]['$polygon'];
          const centerSphere = constraint[key]['$centerSphere'];

          if (polygon !== undefined) {
            let points;

            if (typeof polygon === 'object' && polygon.__type === 'Polygon') {
              if (!polygon.coordinates || polygon.coordinates.length < 3) {
                throw new Parse.Error(Parse.Error.INVALID_JSON, 'bad $geoWithin value; Polygon.coordinates should contain at least 3 lon/lat pairs');
              }

              points = polygon.coordinates;
            } else if (polygon instanceof Array) {
              if (polygon.length < 3) {
                throw new Parse.Error(Parse.Error.INVALID_JSON, 'bad $geoWithin value; $polygon should contain at least 3 GeoPoints');
              }

              points = polygon;
            } else {
              throw new Parse.Error(Parse.Error.INVALID_JSON, "bad $geoWithin value; $polygon should be Polygon object or Array of Parse.GeoPoint's");
            }

            points = points.map(point => {
              if (point instanceof Array && point.length === 2) {
                Parse.GeoPoint._validate(point[1], point[0]);

                return point;
              }

              if (!GeoPointCoder.isValidJSON(point)) {
                throw new Parse.Error(Parse.Error.INVALID_JSON, 'bad $geoWithin value');
              } else {
                Parse.GeoPoint._validate(point.latitude, point.longitude);
              }

              return [point.longitude, point.latitude];
            });
            answer[key] = {
              $polygon: points
            };
          } else if (centerSphere !== undefined) {
            if (!(centerSphere instanceof Array) || centerSphere.length < 2) {
              throw new Parse.Error(Parse.Error.INVALID_JSON, 'bad $geoWithin value; $centerSphere should be an array of Parse.GeoPoint and distance');
            } // Get point, convert to geo point if necessary and validate


            let point = centerSphere[0];

            if (point instanceof Array && point.length === 2) {
              point = new Parse.GeoPoint(point[1], point[0]);
            } else if (!GeoPointCoder.isValidJSON(point)) {
              throw new Parse.Error(Parse.Error.INVALID_JSON, 'bad $geoWithin value; $centerSphere geo point invalid');
            }

            Parse.GeoPoint._validate(point.latitude, point.longitude); // Get distance and validate


            const distance = centerSphere[1];

            if (isNaN(distance) || distance < 0) {
              throw new Parse.Error(Parse.Error.INVALID_JSON, 'bad $geoWithin value; $centerSphere distance invalid');
            }

            answer[key] = {
              $centerSphere: [[point.longitude, point.latitude], distance]
            };
          }

          break;
        }

      case '$geoIntersects':
        {
          const point = constraint[key]['$point'];

          if (!GeoPointCoder.isValidJSON(point)) {
            throw new Parse.Error(Parse.Error.INVALID_JSON, 'bad $geoIntersect value; $point should be GeoPoint');
          } else {
            Parse.GeoPoint._validate(point.latitude, point.longitude);
          }

          answer[key] = {
            $geometry: {
              type: 'Point',
              coordinates: [point.longitude, point.latitude]
            }
          };
          break;
        }

      default:
        if (key.match(/^\$+/)) {
          throw new Parse.Error(Parse.Error.INVALID_JSON, 'bad constraint: ' + key);
        }

        return CannotTransform;
    }
  }

  return answer;
} // Transforms an update operator from REST format to mongo format.
// To be transformed, the input should have an __op field.
// If flatten is true, this will flatten operators to their static
// data format. For example, an increment of 2 would simply become a
// 2.
// The output for a non-flattened operator is a hash with __op being
// the mongo op, and arg being the argument.
// The output for a flattened operator is just a value.
// Returns undefined if this should be a no-op.


function transformUpdateOperator({
  __op,
  amount,
  objects
}, flatten) {
  switch (__op) {
    case 'Delete':
      if (flatten) {
        return undefined;
      } else {
        return {
          __op: '$unset',
          arg: ''
        };
      }

    case 'Increment':
      if (typeof amount !== 'number') {
        throw new Parse.Error(Parse.Error.INVALID_JSON, 'incrementing must provide a number');
      }

      if (flatten) {
        return amount;
      } else {
        return {
          __op: '$inc',
          arg: amount
        };
      }

    case 'Add':
    case 'AddUnique':
      if (!(objects instanceof Array)) {
        throw new Parse.Error(Parse.Error.INVALID_JSON, 'objects to add must be an array');
      }

      var toAdd = objects.map(transformInteriorAtom);

      if (flatten) {
        return toAdd;
      } else {
        var mongoOp = {
          Add: '$push',
          AddUnique: '$addToSet'
        }[__op];
        return {
          __op: mongoOp,
          arg: {
            $each: toAdd
          }
        };
      }

    case 'Remove':
      if (!(objects instanceof Array)) {
        throw new Parse.Error(Parse.Error.INVALID_JSON, 'objects to remove must be an array');
      }

      var toRemove = objects.map(transformInteriorAtom);

      if (flatten) {
        return [];
      } else {
        return {
          __op: '$pullAll',
          arg: toRemove
        };
      }

    default:
      throw new Parse.Error(Parse.Error.COMMAND_UNAVAILABLE, `The ${__op} operator is not supported yet.`);
  }
}

function mapValues(object, iterator) {
  const result = {};
  Object.keys(object).forEach(key => {
    result[key] = iterator(object[key]);
  });
  return result;
}

const nestedMongoObjectToNestedParseObject = mongoObject => {
  switch (typeof mongoObject) {
    case 'string':
    case 'number':
    case 'boolean':
    case 'undefined':
      return mongoObject;

    case 'symbol':
    case 'function':
      throw 'bad value in nestedMongoObjectToNestedParseObject';

    case 'object':
      if (mongoObject === null) {
        return null;
      }

      if (mongoObject instanceof Array) {
        return mongoObject.map(nestedMongoObjectToNestedParseObject);
      }

      if (mongoObject instanceof Date) {
        return Parse._encode(mongoObject);
      }

      if (mongoObject instanceof mongodb.Long) {
        return mongoObject.toNumber();
      }

      if (mongoObject instanceof mongodb.Double) {
        return mongoObject.value;
      }

      if (BytesCoder.isValidDatabaseObject(mongoObject)) {
        return BytesCoder.databaseToJSON(mongoObject);
      }

      if (Object.prototype.hasOwnProperty.call(mongoObject, '__type') && mongoObject.__type == 'Date' && mongoObject.iso instanceof Date) {
        mongoObject.iso = mongoObject.iso.toJSON();
        return mongoObject;
      }

      return mapValues(mongoObject, nestedMongoObjectToNestedParseObject);

    default:
      throw 'unknown js type';
  }
};

const transformPointerString = (schema, field, pointerString) => {
  const objData = pointerString.split('$');

  if (objData[0] !== schema.fields[field].targetClass) {
    throw 'pointer to incorrect className';
  }

  return {
    __type: 'Pointer',
    className: objData[0],
    objectId: objData[1]
  };
}; // Converts from a mongo-format object to a REST-format object.
// Does not strip out anything based on a lack of authentication.


const mongoObjectToParseObject = (className, mongoObject, schema) => {
  switch (typeof mongoObject) {
    case 'string':
    case 'number':
    case 'boolean':
    case 'undefined':
      return mongoObject;

    case 'symbol':
    case 'function':
      throw 'bad value in mongoObjectToParseObject';

    case 'object':
      {
        if (mongoObject === null) {
          return null;
        }

        if (mongoObject instanceof Array) {
          return mongoObject.map(nestedMongoObjectToNestedParseObject);
        }

        if (mongoObject instanceof Date) {
          return Parse._encode(mongoObject);
        }

        if (mongoObject instanceof mongodb.Long) {
          return mongoObject.toNumber();
        }

        if (mongoObject instanceof mongodb.Double) {
          return mongoObject.value;
        }

        if (BytesCoder.isValidDatabaseObject(mongoObject)) {
          return BytesCoder.databaseToJSON(mongoObject);
        }

        const restObject = {};

        if (mongoObject._rperm || mongoObject._wperm) {
          restObject._rperm = mongoObject._rperm || [];
          restObject._wperm = mongoObject._wperm || [];
          delete mongoObject._rperm;
          delete mongoObject._wperm;
        }

        for (var key in mongoObject) {
          switch (key) {
            case '_id':
              restObject['objectId'] = '' + mongoObject[key];
              break;

            case '_hashed_password':
              restObject._hashed_password = mongoObject[key];
              break;

            case '_acl':
              break;

            case '_email_verify_token':
            case '_perishable_token':
            case '_perishable_token_expires_at':
            case '_password_changed_at':
            case '_tombstone':
            case '_email_verify_token_expires_at':
            case '_account_lockout_expires_at':
            case '_failed_login_count':
            case '_password_history':
              // Those keys will be deleted if needed in the DB Controller
              restObject[key] = mongoObject[key];
              break;

            case '_session_token':
              restObject['sessionToken'] = mongoObject[key];
              break;

            case 'updatedAt':
            case '_updated_at':
              restObject['updatedAt'] = Parse._encode(new Date(mongoObject[key])).iso;
              break;

            case 'createdAt':
            case '_created_at':
              restObject['createdAt'] = Parse._encode(new Date(mongoObject[key])).iso;
              break;

            case 'expiresAt':
            case '_expiresAt':
              restObject['expiresAt'] = Parse._encode(new Date(mongoObject[key]));
              break;

            case 'lastUsed':
            case '_last_used':
              restObject['lastUsed'] = Parse._encode(new Date(mongoObject[key])).iso;
              break;

            case 'timesUsed':
            case 'times_used':
              restObject['timesUsed'] = mongoObject[key];
              break;

            case 'authData':
              if (className === '_User') {
                _logger.default.warn('ignoring authData in _User as this key is reserved to be synthesized of `_auth_data_*` keys');
              } else {
                restObject['authData'] = mongoObject[key];
              }

              break;

            default:
              // Check other auth data keys
              var authDataMatch = key.match(/^_auth_data_([a-zA-Z0-9_]+)$/);

              if (authDataMatch && className === '_User') {
                var provider = authDataMatch[1];
                restObject['authData'] = restObject['authData'] || {};
                restObject['authData'][provider] = mongoObject[key];
                break;
              }

              if (key.indexOf('_p_') == 0) {
                var newKey = key.substring(3);

                if (!schema.fields[newKey]) {
                  _logger.default.info('transform.js', 'Found a pointer column not in the schema, dropping it.', className, newKey);

                  break;
                }

                if (schema.fields[newKey].type !== 'Pointer') {
                  _logger.default.info('transform.js', 'Found a pointer in a non-pointer column, dropping it.', className, key);

                  break;
                }

                if (mongoObject[key] === null) {
                  break;
                }

                restObject[newKey] = transformPointerString(schema, newKey, mongoObject[key]);
                break;
              } else if (key[0] == '_' && key != '__type') {
                throw 'bad key in untransform: ' + key;
              } else {
                var value = mongoObject[key];

                if (schema.fields[key] && schema.fields[key].type === 'File' && FileCoder.isValidDatabaseObject(value)) {
                  restObject[key] = FileCoder.databaseToJSON(value);
                  break;
                }

                if (schema.fields[key] && schema.fields[key].type === 'GeoPoint' && GeoPointCoder.isValidDatabaseObject(value)) {
                  restObject[key] = GeoPointCoder.databaseToJSON(value);
                  break;
                }

                if (schema.fields[key] && schema.fields[key].type === 'Polygon' && PolygonCoder.isValidDatabaseObject(value)) {
                  restObject[key] = PolygonCoder.databaseToJSON(value);
                  break;
                }

                if (schema.fields[key] && schema.fields[key].type === 'Bytes' && BytesCoder.isValidDatabaseObject(value)) {
                  restObject[key] = BytesCoder.databaseToJSON(value);
                  break;
                }
              }

              restObject[key] = nestedMongoObjectToNestedParseObject(mongoObject[key]);
          }
        }

        const relationFieldNames = Object.keys(schema.fields).filter(fieldName => schema.fields[fieldName].type === 'Relation');
        const relationFields = {};
        relationFieldNames.forEach(relationFieldName => {
          relationFields[relationFieldName] = {
            __type: 'Relation',
            className: schema.fields[relationFieldName].targetClass
          };
        });
        return _objectSpread(_objectSpread({}, restObject), relationFields);
      }

    default:
      throw 'unknown js type';
  }
};

var DateCoder = {
  JSONToDatabase(json) {
    return new Date(json.iso);
  },

  isValidJSON(value) {
    return typeof value === 'object' && value !== null && value.__type === 'Date';
  }

};
var BytesCoder = {
  base64Pattern: new RegExp('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'),

  isBase64Value(object) {
    if (typeof object !== 'string') {
      return false;
    }

    return this.base64Pattern.test(object);
  },

  databaseToJSON(object) {
    let value;

    if (this.isBase64Value(object)) {
      value = object;
    } else {
      value = object.buffer.toString('base64');
    }

    return {
      __type: 'Bytes',
      base64: value
    };
  },

  isValidDatabaseObject(object) {
    return object instanceof mongodb.Binary || this.isBase64Value(object);
  },

  JSONToDatabase(json) {
    return new mongodb.Binary(Buffer.from(json.base64, 'base64'));
  },

  isValidJSON(value) {
    return typeof value === 'object' && value !== null && value.__type === 'Bytes';
  }

};
var GeoPointCoder = {
  databaseToJSON(object) {
    return {
      __type: 'GeoPoint',
      latitude: object[1],
      longitude: object[0]
    };
  },

  isValidDatabaseObject(object) {
    return object instanceof Array && object.length == 2;
  },

  JSONToDatabase(json) {
    return [json.longitude, json.latitude];
  },

  isValidJSON(value) {
    return typeof value === 'object' && value !== null && value.__type === 'GeoPoint';
  }

};
var PolygonCoder = {
  databaseToJSON(object) {
    // Convert lng/lat -> lat/lng
    const coords = object.coordinates[0].map(coord => {
      return [coord[1], coord[0]];
    });
    return {
      __type: 'Polygon',
      coordinates: coords
    };
  },

  isValidDatabaseObject(object) {
    const coords = object.coordinates[0];

    if (object.type !== 'Polygon' || !(coords instanceof Array)) {
      return false;
    }

    for (let i = 0; i < coords.length; i++) {
      const point = coords[i];

      if (!GeoPointCoder.isValidDatabaseObject(point)) {
        return false;
      }

      Parse.GeoPoint._validate(parseFloat(point[1]), parseFloat(point[0]));
    }

    return true;
  },

  JSONToDatabase(json) {
    let coords = json.coordinates; // Add first point to the end to close polygon

    if (coords[0][0] !== coords[coords.length - 1][0] || coords[0][1] !== coords[coords.length - 1][1]) {
      coords.push(coords[0]);
    }

    const unique = coords.filter((item, index, ar) => {
      let foundIndex = -1;

      for (let i = 0; i < ar.length; i += 1) {
        const pt = ar[i];

        if (pt[0] === item[0] && pt[1] === item[1]) {
          foundIndex = i;
          break;
        }
      }

      return foundIndex === index;
    });

    if (unique.length < 3) {
      throw new Parse.Error(Parse.Error.INTERNAL_SERVER_ERROR, 'GeoJSON: Loop must have at least 3 different vertices');
    } // Convert lat/long -> long/lat


    coords = coords.map(coord => {
      return [coord[1], coord[0]];
    });
    return {
      type: 'Polygon',
      coordinates: [coords]
    };
  },

  isValidJSON(value) {
    return typeof value === 'object' && value !== null && value.__type === 'Polygon';
  }

};
var FileCoder = {
  databaseToJSON(object) {
    return {
      __type: 'File',
      name: object
    };
  },

  isValidDatabaseObject(object) {
    return typeof object === 'string';
  },

  JSONToDatabase(json) {
    return json.name;
  },

  isValidJSON(value) {
    return typeof value === 'object' && value !== null && value.__type === 'File';
  }

};
module.exports = {
  transformKey,
  parseObjectToMongoObjectForCreate,
  transformUpdate,
  transformWhere,
  mongoObjectToParseObject,
  relativeTimeToDate,
  transformConstraint,
  transformPointerString
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9BZGFwdGVycy9TdG9yYWdlL01vbmdvL01vbmdvVHJhbnNmb3JtLmpzIl0sIm5hbWVzIjpbIm1vbmdvZGIiLCJyZXF1aXJlIiwiUGFyc2UiLCJ0cmFuc2Zvcm1LZXkiLCJjbGFzc05hbWUiLCJmaWVsZE5hbWUiLCJzY2hlbWEiLCJmaWVsZHMiLCJfX3R5cGUiLCJ0eXBlIiwidHJhbnNmb3JtS2V5VmFsdWVGb3JVcGRhdGUiLCJyZXN0S2V5IiwicmVzdFZhbHVlIiwicGFyc2VGb3JtYXRTY2hlbWEiLCJrZXkiLCJ0aW1lRmllbGQiLCJpbmNsdWRlcyIsInZhbHVlIiwicGFyc2VJbnQiLCJ0cmFuc2Zvcm1Ub3BMZXZlbEF0b20iLCJDYW5ub3RUcmFuc2Zvcm0iLCJEYXRlIiwiaW5kZXhPZiIsIkFycmF5IiwibWFwIiwidHJhbnNmb3JtSW50ZXJpb3JWYWx1ZSIsInRyYW5zZm9ybVVwZGF0ZU9wZXJhdG9yIiwibWFwVmFsdWVzIiwiaXNSZWdleCIsIlJlZ0V4cCIsImlzU3RhcnRzV2l0aFJlZ2V4IiwibWF0Y2hlcyIsInRvU3RyaW5nIiwibWF0Y2giLCJpc0FsbFZhbHVlc1JlZ2V4T3JOb25lIiwidmFsdWVzIiwiaXNBcnJheSIsImxlbmd0aCIsImZpcnN0VmFsdWVzSXNSZWdleCIsImkiLCJpc0FueVZhbHVlUmVnZXgiLCJzb21lIiwiT2JqZWN0Iiwia2V5cyIsIkVycm9yIiwiSU5WQUxJRF9ORVNURURfS0VZIiwidHJhbnNmb3JtSW50ZXJpb3JBdG9tIiwidmFsdWVBc0RhdGUiLCJ0cmFuc2Zvcm1RdWVyeUtleVZhbHVlIiwiY291bnQiLCJzdWJRdWVyeSIsInRyYW5zZm9ybVdoZXJlIiwiYXV0aERhdGFNYXRjaCIsInByb3ZpZGVyIiwiZXhwZWN0ZWRUeXBlSXNBcnJheSIsImV4cGVjdGVkVHlwZUlzUG9pbnRlciIsImZpZWxkIiwidHJhbnNmb3JtZWRDb25zdHJhaW50IiwidHJhbnNmb3JtQ29uc3RyYWludCIsIiR0ZXh0IiwiJGVsZW1NYXRjaCIsIiRhbGwiLCJ0cmFuc2Zvcm1SZXMiLCJJTlZBTElEX0pTT04iLCJyZXN0V2hlcmUiLCJtb25nb1doZXJlIiwib3V0IiwicGFyc2VPYmplY3RLZXlWYWx1ZVRvTW9uZ29PYmplY3RLZXlWYWx1ZSIsInRyYW5zZm9ybWVkVmFsdWUiLCJjb2VyY2VkVG9EYXRlIiwiSU5WQUxJRF9LRVlfTkFNRSIsInBhcnNlT2JqZWN0VG9Nb25nb09iamVjdEZvckNyZWF0ZSIsInJlc3RDcmVhdGUiLCJhZGRMZWdhY3lBQ0wiLCJtb25nb0NyZWF0ZSIsInVuZGVmaW5lZCIsImNyZWF0ZWRBdCIsIl9jcmVhdGVkX2F0IiwiaXNvIiwidXBkYXRlZEF0IiwiX3VwZGF0ZWRfYXQiLCJ0cmFuc2Zvcm1VcGRhdGUiLCJyZXN0VXBkYXRlIiwibW9uZ29VcGRhdGUiLCJhY2wiLCJfcnBlcm0iLCJfd3Blcm0iLCJfYWNsIiwiJHNldCIsIl9fb3AiLCJhcmciLCJyZXN0T2JqZWN0IiwicmVzdE9iamVjdENvcHkiLCJmb3JFYWNoIiwiZW50cnkiLCJ3IiwiciIsImF0b20iLCJvYmplY3RJZCIsIkRhdGVDb2RlciIsImlzVmFsaWRKU09OIiwiSlNPTlRvRGF0YWJhc2UiLCJCeXRlc0NvZGVyIiwiJHJlZ2V4IiwidGFyZ2V0Q2xhc3MiLCJHZW9Qb2ludENvZGVyIiwiUG9seWdvbkNvZGVyIiwiRmlsZUNvZGVyIiwiSU5URVJOQUxfU0VSVkVSX0VSUk9SIiwicmVsYXRpdmVUaW1lVG9EYXRlIiwidGV4dCIsIm5vdyIsInRvTG93ZXJDYXNlIiwicGFydHMiLCJzcGxpdCIsImZpbHRlciIsInBhcnQiLCJmdXR1cmUiLCJwYXN0Iiwic3RhdHVzIiwiaW5mbyIsInNsaWNlIiwicGFpcnMiLCJwdXNoIiwic2hpZnQiLCJzZWNvbmRzIiwibnVtIiwiaW50ZXJ2YWwiLCJ2YWwiLCJOdW1iZXIiLCJpc0ludGVnZXIiLCJtaWxsaXNlY29uZHMiLCJyZXN1bHQiLCJ2YWx1ZU9mIiwiY29uc3RyYWludCIsImluQXJyYXkiLCJ0cmFuc2Zvcm1GdW5jdGlvbiIsInRyYW5zZm9ybWVyIiwiSlNPTiIsInN0cmluZ2lmeSIsInNvcnQiLCJyZXZlcnNlIiwiYW5zd2VyIiwiJHJlbGF0aXZlVGltZSIsInBhcnNlclJlc3VsdCIsImxvZyIsImFyciIsIl8iLCJmbGF0TWFwIiwicyIsIiRuaW4iLCJzZWFyY2giLCIkc2VhcmNoIiwiJHRlcm0iLCIkbGFuZ3VhZ2UiLCIkY2FzZVNlbnNpdGl2ZSIsIiRkaWFjcml0aWNTZW5zaXRpdmUiLCJwb2ludCIsIiRnZW9XaXRoaW4iLCIkY2VudGVyU3BoZXJlIiwibG9uZ2l0dWRlIiwibGF0aXR1ZGUiLCIkbWF4RGlzdGFuY2UiLCJDT01NQU5EX1VOQVZBSUxBQkxFIiwiYm94IiwiJGJveCIsInBvbHlnb24iLCJjZW50ZXJTcGhlcmUiLCJwb2ludHMiLCJjb29yZGluYXRlcyIsIkdlb1BvaW50IiwiX3ZhbGlkYXRlIiwiJHBvbHlnb24iLCJkaXN0YW5jZSIsImlzTmFOIiwiJGdlb21ldHJ5IiwiYW1vdW50Iiwib2JqZWN0cyIsImZsYXR0ZW4iLCJ0b0FkZCIsIm1vbmdvT3AiLCJBZGQiLCJBZGRVbmlxdWUiLCIkZWFjaCIsInRvUmVtb3ZlIiwib2JqZWN0IiwiaXRlcmF0b3IiLCJuZXN0ZWRNb25nb09iamVjdFRvTmVzdGVkUGFyc2VPYmplY3QiLCJtb25nb09iamVjdCIsIl9lbmNvZGUiLCJMb25nIiwidG9OdW1iZXIiLCJEb3VibGUiLCJpc1ZhbGlkRGF0YWJhc2VPYmplY3QiLCJkYXRhYmFzZVRvSlNPTiIsInByb3RvdHlwZSIsImhhc093blByb3BlcnR5IiwiY2FsbCIsInRvSlNPTiIsInRyYW5zZm9ybVBvaW50ZXJTdHJpbmciLCJwb2ludGVyU3RyaW5nIiwib2JqRGF0YSIsIm1vbmdvT2JqZWN0VG9QYXJzZU9iamVjdCIsIl9oYXNoZWRfcGFzc3dvcmQiLCJ3YXJuIiwibmV3S2V5Iiwic3Vic3RyaW5nIiwicmVsYXRpb25GaWVsZE5hbWVzIiwicmVsYXRpb25GaWVsZHMiLCJyZWxhdGlvbkZpZWxkTmFtZSIsImpzb24iLCJiYXNlNjRQYXR0ZXJuIiwiaXNCYXNlNjRWYWx1ZSIsInRlc3QiLCJidWZmZXIiLCJiYXNlNjQiLCJCaW5hcnkiLCJCdWZmZXIiLCJmcm9tIiwiY29vcmRzIiwiY29vcmQiLCJwYXJzZUZsb2F0IiwidW5pcXVlIiwiaXRlbSIsImluZGV4IiwiYXIiLCJmb3VuZEluZGV4IiwicHQiLCJuYW1lIiwibW9kdWxlIiwiZXhwb3J0cyJdLCJtYXBwaW5ncyI6Ijs7QUFBQTs7QUFDQTs7Ozs7Ozs7OztBQUNBLElBQUlBLE9BQU8sR0FBR0MsT0FBTyxDQUFDLFNBQUQsQ0FBckI7O0FBQ0EsSUFBSUMsS0FBSyxHQUFHRCxPQUFPLENBQUMsWUFBRCxDQUFQLENBQXNCQyxLQUFsQzs7QUFFQSxNQUFNQyxZQUFZLEdBQUcsQ0FBQ0MsU0FBRCxFQUFZQyxTQUFaLEVBQXVCQyxNQUF2QixLQUFrQztBQUNyRDtBQUNBLFVBQVFELFNBQVI7QUFDRSxTQUFLLFVBQUw7QUFDRSxhQUFPLEtBQVA7O0FBQ0YsU0FBSyxXQUFMO0FBQ0UsYUFBTyxhQUFQOztBQUNGLFNBQUssV0FBTDtBQUNFLGFBQU8sYUFBUDs7QUFDRixTQUFLLGNBQUw7QUFDRSxhQUFPLGdCQUFQOztBQUNGLFNBQUssVUFBTDtBQUNFLGFBQU8sWUFBUDs7QUFDRixTQUFLLFdBQUw7QUFDRSxhQUFPLFlBQVA7QUFaSjs7QUFlQSxNQUFJQyxNQUFNLENBQUNDLE1BQVAsQ0FBY0YsU0FBZCxLQUE0QkMsTUFBTSxDQUFDQyxNQUFQLENBQWNGLFNBQWQsRUFBeUJHLE1BQXpCLElBQW1DLFNBQW5FLEVBQThFO0FBQzVFSCxJQUFBQSxTQUFTLEdBQUcsUUFBUUEsU0FBcEI7QUFDRCxHQUZELE1BRU8sSUFBSUMsTUFBTSxDQUFDQyxNQUFQLENBQWNGLFNBQWQsS0FBNEJDLE1BQU0sQ0FBQ0MsTUFBUCxDQUFjRixTQUFkLEVBQXlCSSxJQUF6QixJQUFpQyxTQUFqRSxFQUE0RTtBQUNqRkosSUFBQUEsU0FBUyxHQUFHLFFBQVFBLFNBQXBCO0FBQ0Q7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QUFFLE1BREg7QUFFTDROLE1BQUFBLElBQUksRUFBRTNDO0FBRkQsS0FBUDtBQUlELEdBTmE7O0FBUWRRLEVBQUFBLHFCQUFxQixDQUFDUixNQUFELEVBQVM7QUFDNUIsV0FBTyxPQUFPQSxNQUFQLEtBQWtCLFFBQXpCO0FBQ0QsR0FWYTs7QUFZZHBGLEVBQUFBLGNBQWMsQ0FBQzZHLElBQUQsRUFBTztBQUNuQixXQUFPQSxJQUFJLENBQUNrQixJQUFaO0FBQ0QsR0FkYTs7QUFnQmRoSSxFQUFBQSxXQUFXLENBQUNuRixLQUFELEVBQVE7QUFDakIsV0FBTyxPQUFPQSxLQUFQLEtBQWlCLFFBQWpCLElBQTZCQSxLQUFLLEtBQUssSUFBdkMsSUFBK0NBLEtBQUssQ0FBQ1QsTUFBTixLQUFpQixNQUF2RTtBQUNEOztBQWxCYSxDQUFoQjtBQXFCQTZOLE1BQU0sQ0FBQ0MsT0FBUCxHQUFpQjtBQUNmbk8sRUFBQUEsWUFEZTtBQUVmb0UsRUFBQUEsaUNBRmU7QUFHZlUsRUFBQUEsZUFIZTtBQUlmOUIsRUFBQUEsY0FKZTtBQUtmdUosRUFBQUEsd0JBTGU7QUFNZjdGLEVBQUFBLGtCQU5lO0FBT2ZuRCxFQUFBQSxtQkFQZTtBQVFmNkksRUFBQUE7QUFSZSxDQUFqQiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCBsb2cgZnJvbSAnLi4vLi4vLi4vbG9nZ2VyJztcbmltcG9ydCBfIGZyb20gJ2xvZGFzaCc7XG52YXIgbW9uZ29kYiA9IHJlcXVpcmUoJ21vbmdvZGInKTtcbnZhciBQYXJzZSA9IHJlcXVpcmUoJ3BhcnNlL25vZGUnKS5QYXJzZTtcblxuY29uc3QgdHJhbnNmb3JtS2V5ID0gKGNsYXNzTmFtZSwgZmllbGROYW1lLCBzY2hlbWEpID0+IHtcbiAgLy8gQ2hlY2sgaWYgdGhlIHNjaGVtYSBpcyBrbm93biBzaW5jZSBpdCdzIGEgYnVpbHQtaW4gZmllbGQuXG4gIHN3aXRjaCAoZmllbGROYW1lKSB7XG4gICAgY2FzZSAnb2JqZWN0SWQnOlxuICAgICAgcmV0dXJuICdfaWQnO1xuICAgIGNhc2UgJ2NyZWF0ZWRBdCc6XG4gICAgICByZXR1cm4gJ19jcmVhdGVkX2F0JztcbiAgICBjYXNlICd1cGRhdGVkQXQnOlxuICAgICAgcmV0dXJuICdfdXBkYXRlZF9hdCc7XG4gICAgY2FzZSAnc2Vzc2lvblRva2VuJzpcbiAgICAgIHJldHVybiAnX3Nlc3Npb25fdG9rZW4nO1xuICAgIGNhc2UgJ2xhc3RVc2VkJzpcbiAgICAgIHJldHVybiAnX2xhc3RfdXNlZCc7XG4gICAgY2FzZSAndGltZXNVc2VkJzpcbiAgICAgIHJldHVybiAndGltZXNfdXNlZCc7XG4gIH1cblxuICBpZiAoc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdICYmIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS5fX3R5cGUgPT0gJ1BvaW50ZXInKSB7XG4gICAgZmllbGROYW1lID0gJ19wXycgKyBmaWVsZE5hbWU7XG4gIH0gZWxzZSBpZiAoc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdICYmIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS50eXBlID09ICdQb2ludGVyJykge1xuICAgIGZpZWxkTmFtZSA9ICdfcF8nICsgZmllbGROYW1lO1xuICB9XG5cbiAgcmV0dXJuIGZpZWxkTmFtZTtcbn07XG5cbmNvbnN0IHRyYW5zZm9ybUtleVZhbHVlRm9yVXBkYXRlID0gKGNsYXNzTmFtZSwgcmVzdEtleSwgcmVzdFZhbHVlLCBwYXJzZUZvcm1hdFNjaGVtYSkgPT4ge1xuICAvLyBDaGVjayBpZiB0aGUgc2NoZW1hIGlzIGtub3duIHNpbmNlIGl0J3MgYSBidWlsdC1pbiBmaWVsZC5cbiAgdmFyIGtleSA9IHJlc3RLZXk7XG4gIHZhciB0aW1lRmllbGQgPSBmYWxzZTtcbiAgc3dpdGNoIChrZXkpIHtcbiAgICBjYXNlICdvYmplY3RJZCc6XG4gICAgY2FzZSAnX2lkJzpcbiAgICAgIGlmIChbJ19HbG9iYWxDb25maWcnLCAnX0dyYXBoUUxDb25maWcnXS5pbmNsdWRlcyhjbGFzc05hbWUpKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAga2V5OiBrZXksXG4gICAgICAgICAgdmFsdWU6IHBhcnNlSW50KHJlc3RWYWx1ZSksXG4gICAgICAgIH07XG4gICAgICB9XG4gICAgICBrZXkgPSAnX2lkJztcbiAgICAgIGJyZWFrO1xuICAgIGNhc2UgJ2NyZWF0ZWRBdCc6XG4gICAgY2FzZSAnX2NyZWF0ZWRfYXQnOlxuICAgICAga2V5ID0gJ19jcmVhdGVkX2F0JztcbiAgICAgIHRpbWVGaWVsZCA9IHRydWU7XG4gICAgICBicmVhaztcbiAgICBjYXNlICd1cGRhdGVkQXQnOlxuICAgIGNhc2UgJ191cGRhdGVkX2F0JzpcbiAgICAgIGtleSA9ICdfdXBkYXRlZF9hdCc7XG4gICAgICB0aW1lRmllbGQgPSB0cnVlO1xuICAgICAgYnJlYWs7XG4gICAgY2FzZSAnc2Vzc2lvblRva2VuJzpcbiAgICBjYXNlICdfc2Vzc2lvbl90b2tlbic6XG4gICAgICBrZXkgPSAnX3Nlc3Npb25fdG9rZW4nO1xuICAgICAgYnJlYWs7XG4gICAgY2FzZSAnZXhwaXJlc0F0JzpcbiAgICBjYXNlICdfZXhwaXJlc0F0JzpcbiAgICAgIGtleSA9ICdleHBpcmVzQXQnO1xuICAgICAgdGltZUZpZWxkID0gdHJ1ZTtcbiAgICAgIGJyZWFrO1xuICAgIGNhc2UgJ19lbWFpbF92ZXJpZnlfdG9rZW5fZXhwaXJlc19hdCc6XG4gICAgICBrZXkgPSAnX2VtYWlsX3ZlcmlmeV90b2tlbl9leHBpcmVzX2F0JztcbiAgICAgIHRpbWVGaWVsZCA9IHRydWU7XG4gICAgICBicmVhaztcbiAgICBjYXNlICdfYWNjb3VudF9sb2Nrb3V0X2V4cGlyZXNfYXQnOlxuICAgICAga2V5ID0gJ19hY2NvdW50X2xvY2tvdXRfZXhwaXJlc19hdCc7XG4gICAgICB0aW1lRmllbGQgPSB0cnVlO1xuICAgICAgYnJlYWs7XG4gICAgY2FzZSAnX2ZhaWxlZF9sb2dpbl9jb3VudCc6XG4gICAgICBrZXkgPSAnX2ZhaWxlZF9sb2dpbl9jb3VudCc7XG4gICAgICBicmVhaztcbiAgICBjYXNlICdfcGVyaXNoYWJsZV90b2tlbl9leHBpcmVzX2F0JzpcbiAgICAgIGtleSA9ICdfcGVyaXNoYWJsZV90b2tlbl9leHBpcmVzX2F0JztcbiAgICAgIHRpbWVGaWVsZCA9IHRydWU7XG4gICAgICBicmVhaztcbiAgICBjYXNlICdfcGFzc3dvcmRfY2hhbmdlZF9hdCc6XG4gICAgICBrZXkgPSAnX3Bhc3N3b3JkX2NoYW5nZWRfYXQnO1xuICAgICAgdGltZUZpZWxkID0gdHJ1ZTtcbiAgICAgIGJyZWFrO1xuICAgIGNhc2UgJ19ycGVybSc6XG4gICAgY2FzZSAnX3dwZXJtJzpcbiAgICAgIHJldHVybiB7IGtleToga2V5LCB2YWx1ZTogcmVzdFZhbHVlIH07XG4gICAgY2FzZSAnbGFzdFVzZWQnOlxuICAgIGNhc2UgJ19sYXN0X3VzZWQnOlxuICAgICAga2V5ID0gJ19sYXN0X3VzZWQnO1xuICAgICAgdGltZUZpZWxkID0gdHJ1ZTtcbiAgICAgIGJyZWFrO1xuICAgIGNhc2UgJ3RpbWVzVXNlZCc6XG4gICAgY2FzZSAndGltZXNfdXNlZCc6XG4gICAgICBrZXkgPSAndGltZXNfdXNlZCc7XG4gICAgICB0aW1lRmllbGQgPSB0cnVlO1xuICAgICAgYnJlYWs7XG4gIH1cblxuICBpZiAoXG4gICAgKHBhcnNlRm9ybWF0U2NoZW1hLmZpZWxkc1trZXldICYmIHBhcnNlRm9ybWF0U2NoZW1hLmZpZWxkc1trZXldLnR5cGUgPT09ICdQb2ludGVyJykgfHxcbiAgICAoIWtleS5pbmNsdWRlcygnLicpICYmXG4gICAgICAhcGFyc2VGb3JtYXRTY2hlbWEuZmllbGRzW2tleV0gJiZcbiAgICAgIHJlc3RWYWx1ZSAmJlxuICAgICAgcmVzdFZhbHVlLl9fdHlwZSA9PSAnUG9pbnRlcicpIC8vIERvIG5vdCB1c2UgdGhlIF9wXyBwcmVmaXggZm9yIHBvaW50ZXJzIGluc2lkZSBuZXN0ZWQgZG9jdW1lbnRzXG4gICkge1xuICAgIGtleSA9ICdfcF8nICsga2V5O1xuICB9XG5cbiAgLy8gSGFuZGxlIGF0b21pYyB2YWx1ZXNcbiAgdmFyIHZhbHVlID0gdHJhbnNmb3JtVG9wTGV2ZWxBdG9tKHJlc3RWYWx1ZSk7XG4gIGlmICh2YWx1ZSAhPT0gQ2Fubm90VHJhbnNmb3JtKSB7XG4gICAgaWYgKHRpbWVGaWVsZCAmJiB0eXBlb2YgdmFsdWUgPT09ICdzdHJpbmcnKSB7XG4gICAgICB2YWx1ZSA9IG5ldyBEYXRlKHZhbHVlKTtcbiAgICB9XG4gICAgaWYgKHJlc3RLZXkuaW5kZXhPZignLicpID4gMCkge1xuICAgICAgcmV0dXJuIHsga2V5LCB2YWx1ZTogcmVzdFZhbHVlIH07XG4gICAgfVxuICAgIHJldHVybiB7IGtleSwgdmFsdWUgfTtcbiAgfVxuXG4gIC8vIEhhbmRsZSBhcnJheXNcbiAgaWYgKHJlc3RWYWx1ZSBpbnN0YW5jZW9mIEFycmF5KSB7XG4gICAgdmFsdWUgPSByZXN0VmFsdWUubWFwKHRyYW5zZm9ybUludGVyaW9yVmFsdWUpO1xuICAgIHJldHVybiB7IGtleSwgdmFsdWUgfTtcbiAgfVxuXG4gIC8vIEhhbmRsZSB1cGRhdGUgb3BlcmF0b3JzXG4gIGlmICh0eXBlb2YgcmVzdFZhbHVlID09PSAnb2JqZWN0JyAmJiAnX19vcCcgaW4gcmVzdFZhbHVlKSB7XG4gICAgcmV0dXJuIHsga2V5LCB2YWx1ZTogdHJhbnNmb3JtVXBkYXRlT3BlcmF0b3IocmVzdFZhbHVlLCBmYWxzZSkgfTtcbiAgfVxuXG4gIC8vIEhhbmRsZSBub3JtYWwgb2JqZWN0cyBieSByZWN1cnNpbmdcbiAgdmFsdWUgPSBtYXBWYWx1ZXMocmVzdFZhbHVlLCB0cmFuc2Zvcm1JbnRlcmlvclZhbHVlKTtcbiAgcmV0dXJuIHsga2V5LCB2YWx1ZSB9O1xufTtcblxuY29uc3QgaXNSZWdleCA9IHZhbHVlID0+IHtcbiAgcmV0dXJuIHZhbHVlICYmIHZhbHVlIGluc3RhbmNlb2YgUmVnRXhwO1xufTtcblxuY29uc3QgaXNTdGFydHNXaXRoUmVnZXggPSB2YWx1ZSA9PiB7XG4gIGlmICghaXNSZWdleCh2YWx1ZSkpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICBjb25zdCBtYXRjaGVzID0gdmFsdWUudG9TdHJpbmcoKS5tYXRjaCgvXFwvXFxeXFxcXFEuKlxcXFxFXFwvLyk7XG4gIHJldHVybiAhIW1hdGNoZXM7XG59O1xuXG5jb25zdCBpc0FsbFZhbHVlc1JlZ2V4T3JOb25lID0gdmFsdWVzID0+IHtcbiAgaWYgKCF2YWx1ZXMgfHwgIUFycmF5LmlzQXJyYXkodmFsdWVzKSB8fCB2YWx1ZXMubGVuZ3RoID09PSAwKSB7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICBjb25zdCBmaXJzdFZhbHVlc0lzUmVnZXggPSBpc1N0YXJ0c1dpdGhSZWdleCh2YWx1ZXNbMF0pO1xuICBpZiAodmFsdWVzLmxlbmd0aCA9PT0gMSkge1xuICAgIHJldHVybiBmaXJzdFZhbHVlc0lzUmVnZXg7XG4gIH1cblxuICBmb3IgKGxldCBpID0gMSwgbGVuZ3RoID0gdmFsdWVzLmxlbmd0aDsgaSA8IGxlbmd0aDsgKytpKSB7XG4gICAgaWYgKGZpcnN0VmFsdWVzSXNSZWdleCAhPT0gaXNTdGFydHNXaXRoUmVnZXgodmFsdWVzW2ldKSkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiB0cnVlO1xufTtcblxuY29uc3QgaXNBbnlWYWx1ZVJlZ2V4ID0gdmFsdWVzID0+IHtcbiAgcmV0dXJuIHZhbHVlcy5zb21lKGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgIHJldHVybiBpc1JlZ2V4KHZhbHVlKTtcbiAgfSk7XG59O1xuXG5jb25zdCB0cmFuc2Zvcm1JbnRlcmlvclZhbHVlID0gcmVzdFZhbHVlID0+IHtcbiAgaWYgKFxuICAgIHJlc3RWYWx1ZSAhPT0gbnVsbCAmJlxuICAgIHR5cGVvZiByZXN0VmFsdWUgPT09ICdvYmplY3QnICYmXG4gICAgT2JqZWN0LmtleXMocmVzdFZhbHVlKS5zb21lKGtleSA9PiBrZXkuaW5jbHVkZXMoJyQnKSB8fCBrZXkuaW5jbHVkZXMoJy4nKSlcbiAgKSB7XG4gICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9ORVNURURfS0VZLFxuICAgICAgXCJOZXN0ZWQga2V5cyBzaG91bGQgbm90IGNvbnRhaW4gdGhlICckJyBvciAnLicgY2hhcmFjdGVyc1wiXG4gICAgKTtcbiAgfVxuICAvLyBIYW5kbGUgYXRvbWljIHZhbHVlc1xuICB2YXIgdmFsdWUgPSB0cmFuc2Zvcm1JbnRlcmlvckF0b20ocmVzdFZhbHVlKTtcbiAgaWYgKHZhbHVlICE9PSBDYW5ub3RUcmFuc2Zvcm0pIHtcbiAgICByZXR1cm4gdmFsdWU7XG4gIH1cblxuICAvLyBIYW5kbGUgYXJyYXlzXG4gIGlmIChyZXN0VmFsdWUgaW5zdGFuY2VvZiBBcnJheSkge1xuICAgIHJldHVybiByZXN0VmFsdWUubWFwKHRyYW5zZm9ybUludGVyaW9yVmFsdWUpO1xuICB9XG5cbiAgLy8gSGFuZGxlIHVwZGF0ZSBvcGVyYXRvcnNcbiAgaWYgKHR5cGVvZiByZXN0VmFsdWUgPT09ICdvYmplY3QnICYmICdfX29wJyBpbiByZXN0VmFsdWUpIHtcbiAgICByZXR1cm4gdHJhbnNmb3JtVXBkYXRlT3BlcmF0b3IocmVzdFZhbHVlLCB0cnVlKTtcbiAgfVxuXG4gIC8vIEhhbmRsZSBub3JtYWwgb2JqZWN0cyBieSByZWN1cnNpbmdcbiAgcmV0dXJuIG1hcFZhbHVlcyhyZXN0VmFsdWUsIHRyYW5zZm9ybUludGVyaW9yVmFsdWUpO1xufTtcblxuY29uc3QgdmFsdWVBc0RhdGUgPSB2YWx1ZSA9PiB7XG4gIGlmICh0eXBlb2YgdmFsdWUgPT09ICdzdHJpbmcnKSB7XG4gICAgcmV0dXJuIG5ldyBEYXRlKHZhbHVlKTtcbiAgfSBlbHNlIGlmICh2YWx1ZSBpbnN0YW5jZW9mIERhdGUpIHtcbiAgICByZXR1cm4gdmFsdWU7XG4gIH1cbiAgcmV0dXJuIGZhbHNlO1xufTtcblxuZnVuY3Rpb24gdHJhbnNmb3JtUXVlcnlLZXlWYWx1ZShjbGFzc05hbWUsIGtleSwgdmFsdWUsIHNjaGVtYSwgY291bnQgPSBmYWxzZSkge1xuICBzd2l0Y2ggKGtleSkge1xuICAgIGNhc2UgJ2NyZWF0ZWRBdCc6XG4gICAgICBpZiAodmFsdWVBc0RhdGUodmFsdWUpKSB7XG4gICAgICAgIHJldHVybiB7IGtleTogJ19jcmVhdGVkX2F0JywgdmFsdWU6IHZhbHVlQXNEYXRlKHZhbHVlKSB9O1xuICAgICAgfVxuICAgICAga2V5ID0gJ19jcmVhdGVkX2F0JztcbiAgICAgIGJyZWFrO1xuICAgIGNhc2UgJ3VwZGF0ZWRBdCc6XG4gICAgICBpZiAodmFsdWVBc0RhdGUodmFsdWUpKSB7XG4gICAgICAgIHJldHVybiB7IGtleTogJ191cGRhdGVkX2F0JywgdmFsdWU6IHZhbHVlQXNEYXRlKHZhbHVlKSB9O1xuICAgICAgfVxuICAgICAga2V5ID0gJ191cGRhdGVkX2F0JztcbiAgICAgIGJyZWFrO1xuICAgIGNhc2UgJ2V4cGlyZXNBdCc6XG4gICAgICBpZiAodmFsdWVBc0RhdGUodmFsdWUpKSB7XG4gICAgICAgIHJldHVybiB7IGtleTogJ2V4cGlyZXNBdCcsIHZhbHVlOiB2YWx1ZUFzRGF0ZSh2YWx1ZSkgfTtcbiAgICAgIH1cbiAgICAgIGJyZWFrO1xuICAgIGNhc2UgJ19lbWFpbF92ZXJpZnlfdG9rZW5fZXhwaXJlc19hdCc6XG4gICAgICBpZiAodmFsdWVBc0RhdGUodmFsdWUpKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAga2V5OiAnX2VtYWlsX3ZlcmlmeV90b2tlbl9leHBpcmVzX2F0JyxcbiAgICAgICAgICB2YWx1ZTogdmFsdWVBc0RhdGUodmFsdWUpLFxuICAgICAgICB9O1xuICAgICAgfVxuICAgICAgYnJlYWs7XG4gICAgY2FzZSAnb2JqZWN0SWQnOiB7XG4gICAgICBpZiAoWydfR2xvYmFsQ29uZmlnJywgJ19HcmFwaFFMQ29uZmlnJ10uaW5jbHVkZXMoY2xhc3NOYW1lKSkge1xuICAgICAgICB2YWx1ZSA9IHBhcnNlSW50KHZhbHVlKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiB7IGtleTogJ19pZCcsIHZhbHVlIH07XG4gICAgfVxuICAgIGNhc2UgJ19hY2NvdW50X2xvY2tvdXRfZXhwaXJlc19hdCc6XG4gICAgICBpZiAodmFsdWVBc0RhdGUodmFsdWUpKSB7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAga2V5OiAnX2FjY291bnRfbG9ja291dF9leHBpcmVzX2F0JyxcbiAgICAgICAgICB2YWx1ZTogdmFsdWVBc0RhdGUodmFsdWUpLFxuICAgICAgICB9O1xuICAgICAgfVxuICAgICAgYnJlYWs7XG4gICAgY2FzZSAnX2ZhaWxlZF9sb2dpbl9jb3VudCc6XG4gICAgICByZXR1cm4geyBrZXksIHZhbHVlIH07XG4gICAgY2FzZSAnc2Vzc2lvblRva2VuJzpcbiAgICAgIHJldHVybiB7IGtleTogJ19zZXNzaW9uX3Rva2VuJywgdmFsdWUgfTtcbiAgICBjYXNlICdfcGVyaXNoYWJsZV90b2tlbl9leHBpcmVzX2F0JzpcbiAgICAgIGlmICh2YWx1ZUFzRGF0ZSh2YWx1ZSkpIHtcbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBrZXk6ICdfcGVyaXNoYWJsZV90b2tlbl9leHBpcmVzX2F0JyxcbiAgICAgICAgICB2YWx1ZTogdmFsdWVBc0RhdGUodmFsdWUpLFxuICAgICAgICB9O1xuICAgICAgfVxuICAgICAgYnJlYWs7XG4gICAgY2FzZSAnX3Bhc3N3b3JkX2NoYW5nZWRfYXQnOlxuICAgICAgaWYgKHZhbHVlQXNEYXRlKHZhbHVlKSkge1xuICAgICAgICByZXR1cm4geyBrZXk6ICdfcGFzc3dvcmRfY2hhbmdlZF9hdCcsIHZhbHVlOiB2YWx1ZUFzRGF0ZSh2YWx1ZSkgfTtcbiAgICAgIH1cbiAgICAgIGJyZWFrO1xuICAgIGNhc2UgJ19ycGVybSc6XG4gICAgY2FzZSAnX3dwZXJtJzpcbiAgICBjYXNlICdfcGVyaXNoYWJsZV90b2tlbic6XG4gICAgY2FzZSAnX2VtYWlsX3ZlcmlmeV90b2tlbic6XG4gICAgICByZXR1cm4geyBrZXksIHZhbHVlIH07XG4gICAgY2FzZSAnJG9yJzpcbiAgICBjYXNlICckYW5kJzpcbiAgICBjYXNlICckbm9yJzpcbiAgICAgIHJldHVybiB7XG4gICAgICAgIGtleToga2V5LFxuICAgICAgICB2YWx1ZTogdmFsdWUubWFwKHN1YlF1ZXJ5ID0+IHRyYW5zZm9ybVdoZXJlKGNsYXNzTmFtZSwgc3ViUXVlcnksIHNjaGVtYSwgY291bnQpKSxcbiAgICAgIH07XG4gICAgY2FzZSAnbGFzdFVzZWQnOlxuICAgICAgaWYgKHZhbHVlQXNEYXRlKHZhbHVlKSkge1xuICAgICAgICByZXR1cm4geyBrZXk6ICdfbGFzdF91c2VkJywgdmFsdWU6IHZhbHVlQXNEYXRlKHZhbHVlKSB9O1xuICAgICAgfVxuICAgICAga2V5ID0gJ19sYXN0X3VzZWQnO1xuICAgICAgYnJlYWs7XG4gICAgY2FzZSAndGltZXNVc2VkJzpcbiAgICAgIHJldHVybiB7IGtleTogJ3RpbWVzX3VzZWQnLCB2YWx1ZTogdmFsdWUgfTtcbiAgICBkZWZhdWx0OiB7XG4gICAgICAvLyBPdGhlciBhdXRoIGRhdGFcbiAgICAgIGNvbnN0IGF1dGhEYXRhTWF0Y2ggPSBrZXkubWF0Y2goL15hdXRoRGF0YVxcLihbYS16QS1aMC05X10rKVxcLmlkJC8pO1xuICAgICAgaWYgKGF1dGhEYXRhTWF0Y2gpIHtcbiAgICAgICAgY29uc3QgcHJvdmlkZXIgPSBhdXRoRGF0YU1hdGNoWzFdO1xuICAgICAgICAvLyBTcGVjaWFsLWNhc2UgYXV0aCBkYXRhLlxuICAgICAgICByZXR1cm4geyBrZXk6IGBfYXV0aF9kYXRhXyR7cHJvdmlkZXJ9LmlkYCwgdmFsdWUgfTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBjb25zdCBleHBlY3RlZFR5cGVJc0FycmF5ID0gc2NoZW1hICYmIHNjaGVtYS5maWVsZHNba2V5XSAmJiBzY2hlbWEuZmllbGRzW2tleV0udHlwZSA9PT0gJ0FycmF5JztcblxuICBjb25zdCBleHBlY3RlZFR5cGVJc1BvaW50ZXIgPVxuICAgIHNjaGVtYSAmJiBzY2hlbWEuZmllbGRzW2tleV0gJiYgc2NoZW1hLmZpZWxkc1trZXldLnR5cGUgPT09ICdQb2ludGVyJztcblxuICBjb25zdCBmaWVsZCA9IHNjaGVtYSAmJiBzY2hlbWEuZmllbGRzW2tleV07XG4gIGlmIChcbiAgICBleHBlY3RlZFR5cGVJc1BvaW50ZXIgfHxcbiAgICAoIXNjaGVtYSAmJiAha2V5LmluY2x1ZGVzKCcuJykgJiYgdmFsdWUgJiYgdmFsdWUuX190eXBlID09PSAnUG9pbnRlcicpXG4gICkge1xuICAgIGtleSA9ICdfcF8nICsga2V5O1xuICB9XG5cbiAgLy8gSGFuZGxlIHF1ZXJ5IGNvbnN0cmFpbnRzXG4gIGNvbnN0IHRyYW5zZm9ybWVkQ29uc3RyYWludCA9IHRyYW5zZm9ybUNvbnN0cmFpbnQodmFsdWUsIGZpZWxkLCBjb3VudCk7XG4gIGlmICh0cmFuc2Zvcm1lZENvbnN0cmFpbnQgIT09IENhbm5vdFRyYW5zZm9ybSkge1xuICAgIGlmICh0cmFuc2Zvcm1lZENvbnN0cmFpbnQuJHRleHQpIHtcbiAgICAgIHJldHVybiB7IGtleTogJyR0ZXh0JywgdmFsdWU6IHRyYW5zZm9ybWVkQ29uc3RyYWludC4kdGV4dCB9O1xuICAgIH1cbiAgICBpZiAodHJhbnNmb3JtZWRDb25zdHJhaW50LiRlbGVtTWF0Y2gpIHtcbiAgICAgIHJldHVybiB7IGtleTogJyRub3InLCB2YWx1ZTogW3sgW2tleV06IHRyYW5zZm9ybWVkQ29uc3RyYWludCB9XSB9O1xuICAgIH1cbiAgICByZXR1cm4geyBrZXksIHZhbHVlOiB0cmFuc2Zvcm1lZENvbnN0cmFpbnQgfTtcbiAgfVxuXG4gIGlmIChleHBlY3RlZFR5cGVJc0FycmF5ICYmICEodmFsdWUgaW5zdGFuY2VvZiBBcnJheSkpIHtcbiAgICByZXR1cm4geyBrZXksIHZhbHVlOiB7ICRhbGw6IFt0cmFuc2Zvcm1JbnRlcmlvckF0b20odmFsdWUpXSB9IH07XG4gIH1cblxuICAvLyBIYW5kbGUgYXRvbWljIHZhbHVlc1xuICB2YXIgdHJhbnNmb3JtUmVzID0ga2V5LmluY2x1ZGVzKCcuJylcbiAgICA/IHRyYW5zZm9ybUludGVyaW9yQXRvbSh2YWx1ZSlcbiAgICA6IHRyYW5zZm9ybVRvcExldmVsQXRvbSh2YWx1ZSk7XG4gIGlmICh0cmFuc2Zvcm1SZXMgIT09IENhbm5vdFRyYW5zZm9ybSkge1xuICAgIHJldHVybiB7IGtleSwgdmFsdWU6IHRyYW5zZm9ybVJlcyB9O1xuICB9IGVsc2Uge1xuICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgIGBZb3UgY2Fubm90IHVzZSAke3ZhbHVlfSBhcyBhIHF1ZXJ5IHBhcmFtZXRlci5gXG4gICAgKTtcbiAgfVxufVxuXG4vLyBNYWluIGV4cG9zZWQgbWV0aG9kIHRvIGhlbHAgcnVuIHF1ZXJpZXMuXG4vLyByZXN0V2hlcmUgaXMgdGhlIFwid2hlcmVcIiBjbGF1c2UgaW4gUkVTVCBBUEkgZm9ybS5cbi8vIFJldHVybnMgdGhlIG1vbmdvIGZvcm0gb2YgdGhlIHF1ZXJ5LlxuZnVuY3Rpb24gdHJhbnNmb3JtV2hlcmUoY2xhc3NOYW1lLCByZXN0V2hlcmUsIHNjaGVtYSwgY291bnQgPSBmYWxzZSkge1xuICBjb25zdCBtb25nb1doZXJlID0ge307XG4gIGZvciAoY29uc3QgcmVzdEtleSBpbiByZXN0V2hlcmUpIHtcbiAgICBjb25zdCBvdXQgPSB0cmFuc2Zvcm1RdWVyeUtleVZhbHVlKGNsYXNzTmFtZSwgcmVzdEtleSwgcmVzdFdoZXJlW3Jlc3RLZXldLCBzY2hlbWEsIGNvdW50KTtcbiAgICBtb25nb1doZXJlW291dC5rZXldID0gb3V0LnZhbHVlO1xuICB9XG4gIHJldHVybiBtb25nb1doZXJlO1xufVxuXG5jb25zdCBwYXJzZU9iamVjdEtleVZhbHVlVG9Nb25nb09iamVjdEtleVZhbHVlID0gKHJlc3RLZXksIHJlc3RWYWx1ZSwgc2NoZW1hKSA9PiB7XG4gIC8vIENoZWNrIGlmIHRoZSBzY2hlbWEgaXMga25vd24gc2luY2UgaXQncyBhIGJ1aWx0LWluIGZpZWxkLlxuICBsZXQgdHJhbnNmb3JtZWRWYWx1ZTtcbiAgbGV0IGNvZXJjZWRUb0RhdGU7XG4gIHN3aXRjaCAocmVzdEtleSkge1xuICAgIGNhc2UgJ29iamVjdElkJzpcbiAgICAgIHJldHVybiB7IGtleTogJ19pZCcsIHZhbHVlOiByZXN0VmFsdWUgfTtcbiAgICBjYXNlICdleHBpcmVzQXQnOlxuICAgICAgdHJhbnNmb3JtZWRWYWx1ZSA9IHRyYW5zZm9ybVRvcExldmVsQXRvbShyZXN0VmFsdWUpO1xuICAgICAgY29lcmNlZFRvRGF0ZSA9XG4gICAgICAgIHR5cGVvZiB0cmFuc2Zvcm1lZFZhbHVlID09PSAnc3RyaW5nJyA/IG5ldyBEYXRlKHRyYW5zZm9ybWVkVmFsdWUpIDogdHJhbnNmb3JtZWRWYWx1ZTtcbiAgICAgIHJldHVybiB7IGtleTogJ2V4cGlyZXNBdCcsIHZhbHVlOiBjb2VyY2VkVG9EYXRlIH07XG4gICAgY2FzZSAnX2VtYWlsX3ZlcmlmeV90b2tlbl9leHBpcmVzX2F0JzpcbiAgICAgIHRyYW5zZm9ybWVkVmFsdWUgPSB0cmFuc2Zvcm1Ub3BMZXZlbEF0b20ocmVzdFZhbHVlKTtcbiAgICAgIGNvZXJjZWRUb0RhdGUgPVxuICAgICAgICB0eXBlb2YgdHJhbnNmb3JtZWRWYWx1ZSA9PT0gJ3N0cmluZycgPyBuZXcgRGF0ZSh0cmFuc2Zvcm1lZFZhbHVlKSA6IHRyYW5zZm9ybWVkVmFsdWU7XG4gICAgICByZXR1cm4geyBrZXk6ICdfZW1haWxfdmVyaWZ5X3Rva2VuX2V4cGlyZXNfYXQnLCB2YWx1ZTogY29lcmNlZFRvRGF0ZSB9O1xuICAgIGNhc2UgJ19hY2NvdW50X2xvY2tvdXRfZXhwaXJlc19hdCc6XG4gICAgICB0cmFuc2Zvcm1lZFZhbHVlID0gdHJhbnNmb3JtVG9wTGV2ZWxBdG9tKHJlc3RWYWx1ZSk7XG4gICAgICBjb2VyY2VkVG9EYXRlID1cbiAgICAgICAgdHlwZW9mIHRyYW5zZm9ybWVkVmFsdWUgPT09ICdzdHJpbmcnID8gbmV3IERhdGUodHJhbnNmb3JtZWRWYWx1ZSkgOiB0cmFuc2Zvcm1lZFZhbHVlO1xuICAgICAgcmV0dXJuIHsga2V5OiAnX2FjY291bnRfbG9ja291dF9leHBpcmVzX2F0JywgdmFsdWU6IGNvZXJjZWRUb0RhdGUgfTtcbiAgICBjYXNlICdfcGVyaXNoYWJsZV90b2tlbl9leHBpcmVzX2F0JzpcbiAgICAgIHRyYW5zZm9ybWVkVmFsdWUgPSB0cmFuc2Zvcm1Ub3BMZXZlbEF0b20ocmVzdFZhbHVlKTtcbiAgICAgIGNvZXJjZWRUb0RhdGUgPVxuICAgICAgICB0eXBlb2YgdHJhbnNmb3JtZWRWYWx1ZSA9PT0gJ3N0cmluZycgPyBuZXcgRGF0ZSh0cmFuc2Zvcm1lZFZhbHVlKSA6IHRyYW5zZm9ybWVkVmFsdWU7XG4gICAgICByZXR1cm4geyBrZXk6ICdfcGVyaXNoYWJsZV90b2tlbl9leHBpcmVzX2F0JywgdmFsdWU6IGNvZXJjZWRUb0RhdGUgfTtcbiAgICBjYXNlICdfcGFzc3dvcmRfY2hhbmdlZF9hdCc6XG4gICAgICB0cmFuc2Zvcm1lZFZhbHVlID0gdHJhbnNmb3JtVG9wTGV2ZWxBdG9tKHJlc3RWYWx1ZSk7XG4gICAgICBjb2VyY2VkVG9EYXRlID1cbiAgICAgICAgdHlwZW9mIHRyYW5zZm9ybWVkVmFsdWUgPT09ICdzdHJpbmcnID8gbmV3IERhdGUodHJhbnNmb3JtZWRWYWx1ZSkgOiB0cmFuc2Zvcm1lZFZhbHVlO1xuICAgICAgcmV0dXJuIHsga2V5OiAnX3Bhc3N3b3JkX2NoYW5nZWRfYXQnLCB2YWx1ZTogY29lcmNlZFRvRGF0ZSB9O1xuICAgIGNhc2UgJ19mYWlsZWRfbG9naW5fY291bnQnOlxuICAgIGNhc2UgJ19ycGVybSc6XG4gICAgY2FzZSAnX3dwZXJtJzpcbiAgICBjYXNlICdfZW1haWxfdmVyaWZ5X3Rva2VuJzpcbiAgICBjYXNlICdfaGFzaGVkX3Bhc3N3b3JkJzpcbiAgICBjYXNlICdfcGVyaXNoYWJsZV90b2tlbic6XG4gICAgICByZXR1cm4geyBrZXk6IHJlc3RLZXksIHZhbHVlOiByZXN0VmFsdWUgfTtcbiAgICBjYXNlICdzZXNzaW9uVG9rZW4nOlxuICAgICAgcmV0dXJuIHsga2V5OiAnX3Nlc3Npb25fdG9rZW4nLCB2YWx1ZTogcmVzdFZhbHVlIH07XG4gICAgZGVmYXVsdDpcbiAgICAgIC8vIEF1dGggZGF0YSBzaG91bGQgaGF2ZSBiZWVuIHRyYW5zZm9ybWVkIGFscmVhZHlcbiAgICAgIGlmIChyZXN0S2V5Lm1hdGNoKC9eYXV0aERhdGFcXC4oW2EtekEtWjAtOV9dKylcXC5pZCQvKSkge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9LRVlfTkFNRSwgJ2NhbiBvbmx5IHF1ZXJ5IG9uICcgKyByZXN0S2V5KTtcbiAgICAgIH1cbiAgICAgIC8vIFRydXN0IHRoYXQgdGhlIGF1dGggZGF0YSBoYXMgYmVlbiB0cmFuc2Zvcm1lZCBhbmQgc2F2ZSBpdCBkaXJlY3RseVxuICAgICAgaWYgKHJlc3RLZXkubWF0Y2goL15fYXV0aF9kYXRhX1thLXpBLVowLTlfXSskLykpIHtcbiAgICAgICAgcmV0dXJuIHsga2V5OiByZXN0S2V5LCB2YWx1ZTogcmVzdFZhbHVlIH07XG4gICAgICB9XG4gIH1cbiAgLy9za2lwIHN0cmFpZ2h0IHRvIHRyYW5zZm9ybVRvcExldmVsQXRvbSBmb3IgQnl0ZXMsIHRoZXkgZG9uJ3Qgc2hvdyB1cCBpbiB0aGUgc2NoZW1hIGZvciBzb21lIHJlYXNvblxuICBpZiAocmVzdFZhbHVlICYmIHJlc3RWYWx1ZS5fX3R5cGUgIT09ICdCeXRlcycpIHtcbiAgICAvL05vdGU6IFdlIG1heSBub3Qga25vdyB0aGUgdHlwZSBvZiBhIGZpZWxkIGhlcmUsIGFzIHRoZSB1c2VyIGNvdWxkIGJlIHNhdmluZyAobnVsbCkgdG8gYSBmaWVsZFxuICAgIC8vVGhhdCBuZXZlciBleGlzdGVkIGJlZm9yZSwgbWVhbmluZyB3ZSBjYW4ndCBpbmZlciB0aGUgdHlwZS5cbiAgICBpZiAoXG4gICAgICAoc2NoZW1hLmZpZWxkc1tyZXN0S2V5XSAmJiBzY2hlbWEuZmllbGRzW3Jlc3RLZXldLnR5cGUgPT0gJ1BvaW50ZXInKSB8fFxuICAgICAgcmVzdFZhbHVlLl9fdHlwZSA9PSAnUG9pbnRlcidcbiAgICApIHtcbiAgICAgIHJlc3RLZXkgPSAnX3BfJyArIHJlc3RLZXk7XG4gICAgfVxuICB9XG5cbiAgLy8gSGFuZGxlIGF0b21pYyB2YWx1ZXNcbiAgdmFyIHZhbHVlID0gdHJhbnNmb3JtVG9wTGV2ZWxBdG9tKHJlc3RWYWx1ZSk7XG4gIGlmICh2YWx1ZSAhPT0gQ2Fubm90VHJhbnNmb3JtKSB7XG4gICAgcmV0dXJuIHsga2V5OiByZXN0S2V5LCB2YWx1ZTogdmFsdWUgfTtcbiAgfVxuXG4gIC8vIEFDTHMgYXJlIGhhbmRsZWQgYmVmb3JlIHRoaXMgbWV0aG9kIGlzIGNhbGxlZFxuICAvLyBJZiBhbiBBQ0wga2V5IHN0aWxsIGV4aXN0cyBoZXJlLCBzb21ldGhpbmcgaXMgd3JvbmcuXG4gIGlmIChyZXN0S2V5ID09PSAnQUNMJykge1xuICAgIHRocm93ICdUaGVyZSB3YXMgYSBwcm9ibGVtIHRyYW5zZm9ybWluZyBhbiBBQ0wuJztcbiAgfVxuXG4gIC8vIEhhbmRsZSBhcnJheXNcbiAgaWYgKHJlc3RWYWx1ZSBpbnN0YW5jZW9mIEFycmF5KSB7XG4gICAgdmFsdWUgPSByZXN0VmFsdWUubWFwKHRyYW5zZm9ybUludGVyaW9yVmFsdWUpO1xuICAgIHJldHVybiB7IGtleTogcmVzdEtleSwgdmFsdWU6IHZhbHVlIH07XG4gIH1cblxuICAvLyBIYW5kbGUgbm9ybWFsIG9iamVjdHMgYnkgcmVjdXJzaW5nXG4gIGlmIChPYmplY3Qua2V5cyhyZXN0VmFsdWUpLnNvbWUoa2V5ID0+IGtleS5pbmNsdWRlcygnJCcpIHx8IGtleS5pbmNsdWRlcygnLicpKSkge1xuICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfTkVTVEVEX0tFWSxcbiAgICAgIFwiTmVzdGVkIGtleXMgc2hvdWxkIG5vdCBjb250YWluIHRoZSAnJCcgb3IgJy4nIGNoYXJhY3RlcnNcIlxuICAgICk7XG4gIH1cbiAgdmFsdWUgPSBtYXBWYWx1ZXMocmVzdFZhbHVlLCB0cmFuc2Zvcm1JbnRlcmlvclZhbHVlKTtcbiAgcmV0dXJuIHsga2V5OiByZXN0S2V5LCB2YWx1ZSB9O1xufTtcblxuY29uc3QgcGFyc2VPYmplY3RUb01vbmdvT2JqZWN0Rm9yQ3JlYXRlID0gKGNsYXNzTmFtZSwgcmVzdENyZWF0ZSwgc2NoZW1hKSA9PiB7XG4gIHJlc3RDcmVhdGUgPSBhZGRMZWdhY3lBQ0wocmVzdENyZWF0ZSk7XG4gIGNvbnN0IG1vbmdvQ3JlYXRlID0ge307XG4gIGZvciAoY29uc3QgcmVzdEtleSBpbiByZXN0Q3JlYXRlKSB7XG4gICAgaWYgKHJlc3RDcmVhdGVbcmVzdEtleV0gJiYgcmVzdENyZWF0ZVtyZXN0S2V5XS5fX3R5cGUgPT09ICdSZWxhdGlvbicpIHtcbiAgICAgIGNvbnRpbnVlO1xuICAgIH1cbiAgICBjb25zdCB7IGtleSwgdmFsdWUgfSA9IHBhcnNlT2JqZWN0S2V5VmFsdWVUb01vbmdvT2JqZWN0S2V5VmFsdWUoXG4gICAgICByZXN0S2V5LFxuICAgICAgcmVzdENyZWF0ZVtyZXN0S2V5XSxcbiAgICAgIHNjaGVtYVxuICAgICk7XG4gICAgaWYgKHZhbHVlICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIG1vbmdvQ3JlYXRlW2tleV0gPSB2YWx1ZTtcbiAgICB9XG4gIH1cblxuICAvLyBVc2UgdGhlIGxlZ2FjeSBtb25nbyBmb3JtYXQgZm9yIGNyZWF0ZWRBdCBhbmQgdXBkYXRlZEF0XG4gIGlmIChtb25nb0NyZWF0ZS5jcmVhdGVkQXQpIHtcbiAgICBtb25nb0NyZWF0ZS5fY3JlYXRlZF9hdCA9IG5ldyBEYXRlKG1vbmdvQ3JlYXRlLmNyZWF0ZWRBdC5pc28gfHwgbW9uZ29DcmVhdGUuY3JlYXRlZEF0KTtcbiAgICBkZWxldGUgbW9uZ29DcmVhdGUuY3JlYXRlZEF0O1xuICB9XG4gIGlmIChtb25nb0NyZWF0ZS51cGRhdGVkQXQpIHtcbiAgICBtb25nb0NyZWF0ZS5fdXBkYXRlZF9hdCA9IG5ldyBEYXRlKG1vbmdvQ3JlYXRlLnVwZGF0ZWRBdC5pc28gfHwgbW9uZ29DcmVhdGUudXBkYXRlZEF0KTtcbiAgICBkZWxldGUgbW9uZ29DcmVhdGUudXBkYXRlZEF0O1xuICB9XG5cbiAgcmV0dXJuIG1vbmdvQ3JlYXRlO1xufTtcblxuLy8gTWFpbiBleHBvc2VkIG1ldGhvZCB0byBoZWxwIHVwZGF0ZSBvbGQgb2JqZWN0cy5cbmNvbnN0IHRyYW5zZm9ybVVwZGF0ZSA9IChjbGFzc05hbWUsIHJlc3RVcGRhdGUsIHBhcnNlRm9ybWF0U2NoZW1hKSA9PiB7XG4gIGNvbnN0IG1vbmdvVXBkYXRlID0ge307XG4gIGNvbnN0IGFjbCA9IGFkZExlZ2FjeUFDTChyZXN0VXBkYXRlKTtcbiAgaWYgKGFjbC5fcnBlcm0gfHwgYWNsLl93cGVybSB8fCBhY2wuX2FjbCkge1xuICAgIG1vbmdvVXBkYXRlLiRzZXQgPSB7fTtcbiAgICBpZiAoYWNsLl9ycGVybSkge1xuICAgICAgbW9uZ29VcGRhdGUuJHNldC5fcnBlcm0gPSBhY2wuX3JwZXJtO1xuICAgIH1cbiAgICBpZiAoYWNsLl93cGVybSkge1xuICAgICAgbW9uZ29VcGRhdGUuJHNldC5fd3Blcm0gPSBhY2wuX3dwZXJtO1xuICAgIH1cbiAgICBpZiAoYWNsLl9hY2wpIHtcbiAgICAgIG1vbmdvVXBkYXRlLiRzZXQuX2FjbCA9IGFjbC5fYWNsO1xuICAgIH1cbiAgfVxuICBmb3IgKHZhciByZXN0S2V5IGluIHJlc3RVcGRhdGUpIHtcbiAgICBpZiAocmVzdFVwZGF0ZVtyZXN0S2V5XSAmJiByZXN0VXBkYXRlW3Jlc3RLZXldLl9fdHlwZSA9PT0gJ1JlbGF0aW9uJykge1xuICAgICAgY29udGludWU7XG4gICAgfVxuICAgIHZhciBvdXQgPSB0cmFuc2Zvcm1LZXlWYWx1ZUZvclVwZGF0ZShcbiAgICAgIGNsYXNzTmFtZSxcbiAgICAgIHJlc3RLZXksXG4gICAgICByZXN0VXBkYXRlW3Jlc3RLZXldLFxuICAgICAgcGFyc2VGb3JtYXRTY2hlbWFcbiAgICApO1xuXG4gICAgLy8gSWYgdGhlIG91dHB1dCB2YWx1ZSBpcyBhbiBvYmplY3Qgd2l0aCBhbnkgJCBrZXlzLCBpdCdzIGFuXG4gICAgLy8gb3BlcmF0b3IgdGhhdCBuZWVkcyB0byBiZSBsaWZ0ZWQgb250byB0aGUgdG9wIGxldmVsIHVwZGF0ZVxuICAgIC8vIG9iamVjdC5cbiAgICBpZiAodHlwZW9mIG91dC52YWx1ZSA9PT0gJ29iamVjdCcgJiYgb3V0LnZhbHVlICE9PSBudWxsICYmIG91dC52YWx1ZS5fX29wKSB7XG4gICAgICBtb25nb1VwZGF0ZVtvdXQudmFsdWUuX19vcF0gPSBtb25nb1VwZGF0ZVtvdXQudmFsdWUuX19vcF0gfHwge307XG4gICAgICBtb25nb1VwZGF0ZVtvdXQudmFsdWUuX19vcF1bb3V0LmtleV0gPSBvdXQudmFsdWUuYXJnO1xuICAgIH0gZWxzZSB7XG4gICAgICBtb25nb1VwZGF0ZVsnJHNldCddID0gbW9uZ29VcGRhdGVbJyRzZXQnXSB8fCB7fTtcbiAgICAgIG1vbmdvVXBkYXRlWyckc2V0J11bb3V0LmtleV0gPSBvdXQudmFsdWU7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIG1vbmdvVXBkYXRlO1xufTtcblxuLy8gQWRkIHRoZSBsZWdhY3kgX2FjbCBmb3JtYXQuXG5jb25zdCBhZGRMZWdhY3lBQ0wgPSByZXN0T2JqZWN0ID0+IHtcbiAgY29uc3QgcmVzdE9iamVjdENvcHkgPSB7IC4uLnJlc3RPYmplY3QgfTtcbiAgY29uc3QgX2FjbCA9IHt9O1xuXG4gIGlmIChyZXN0T2JqZWN0Ll93cGVybSkge1xuICAgIHJlc3RPYmplY3QuX3dwZXJtLmZvckVhY2goZW50cnkgPT4ge1xuICAgICAgX2FjbFtlbnRyeV0gPSB7IHc6IHRydWUgfTtcbiAgICB9KTtcbiAgICByZXN0T2JqZWN0Q29weS5fYWNsID0gX2FjbDtcbiAgfVxuXG4gIGlmIChyZXN0T2JqZWN0Ll9ycGVybSkge1xuICAgIHJlc3RPYmplY3QuX3JwZXJtLmZvckVhY2goZW50cnkgPT4ge1xuICAgICAgaWYgKCEoZW50cnkgaW4gX2FjbCkpIHtcbiAgICAgICAgX2FjbFtlbnRyeV0gPSB7IHI6IHRydWUgfTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIF9hY2xbZW50cnldLnIgPSB0cnVlO1xuICAgICAgfVxuICAgIH0pO1xuICAgIHJlc3RPYmplY3RDb3B5Ll9hY2wgPSBfYWNsO1xuICB9XG5cbiAgcmV0dXJuIHJlc3RPYmplY3RDb3B5O1xufTtcblxuLy8gQSBzZW50aW5lbCB2YWx1ZSB0aGF0IGhlbHBlciB0cmFuc2Zvcm1hdGlvbnMgcmV0dXJuIHdoZW4gdGhleVxuLy8gY2Fubm90IHBlcmZvcm0gYSB0cmFuc2Zvcm1hdGlvblxuZnVuY3Rpb24gQ2Fubm90VHJhbnNmb3JtKCkge31cblxuY29uc3QgdHJhbnNmb3JtSW50ZXJpb3JBdG9tID0gYXRvbSA9PiB7XG4gIC8vIFRPRE86IGNoZWNrIHZhbGlkaXR5IGhhcmRlciBmb3IgdGhlIF9fdHlwZS1kZWZpbmVkIHR5cGVzXG4gIGlmICh0eXBlb2YgYXRvbSA9PT0gJ29iamVjdCcgJiYgYXRvbSAmJiAhKGF0b20gaW5zdGFuY2VvZiBEYXRlKSAmJiBhdG9tLl9fdHlwZSA9PT0gJ1BvaW50ZXInKSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIF9fdHlwZTogJ1BvaW50ZXInLFxuICAgICAgY2xhc3NOYW1lOiBhdG9tLmNsYXNzTmFtZSxcbiAgICAgIG9iamVjdElkOiBhdG9tLm9iamVjdElkLFxuICAgIH07XG4gIH0gZWxzZSBpZiAodHlwZW9mIGF0b20gPT09ICdmdW5jdGlvbicgfHwgdHlwZW9mIGF0b20gPT09ICdzeW1ib2wnKSB7XG4gICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgYGNhbm5vdCB0cmFuc2Zvcm0gdmFsdWU6ICR7YXRvbX1gKTtcbiAgfSBlbHNlIGlmIChEYXRlQ29kZXIuaXNWYWxpZEpTT04oYXRvbSkpIHtcbiAgICByZXR1cm4gRGF0ZUNvZGVyLkpTT05Ub0RhdGFiYXNlKGF0b20pO1xuICB9IGVsc2UgaWYgKEJ5dGVzQ29kZXIuaXNWYWxpZEpTT04oYXRvbSkpIHtcbiAgICByZXR1cm4gQnl0ZXNDb2Rlci5KU09OVG9EYXRhYmFzZShhdG9tKTtcbiAgfSBlbHNlIGlmICh0eXBlb2YgYXRvbSA9PT0gJ29iamVjdCcgJiYgYXRvbSAmJiBhdG9tLiRyZWdleCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgcmV0dXJuIG5ldyBSZWdFeHAoYXRvbS4kcmVnZXgpO1xuICB9IGVsc2Uge1xuICAgIHJldHVybiBhdG9tO1xuICB9XG59O1xuXG4vLyBIZWxwZXIgZnVuY3Rpb24gdG8gdHJhbnNmb3JtIGFuIGF0b20gZnJvbSBSRVNUIGZvcm1hdCB0byBNb25nbyBmb3JtYXQuXG4vLyBBbiBhdG9tIGlzIGFueXRoaW5nIHRoYXQgY2FuJ3QgY29udGFpbiBvdGhlciBleHByZXNzaW9ucy4gU28gaXRcbi8vIGluY2x1ZGVzIHRoaW5ncyB3aGVyZSBvYmplY3RzIGFyZSB1c2VkIHRvIHJlcHJlc2VudCBvdGhlclxuLy8gZGF0YXR5cGVzLCBsaWtlIHBvaW50ZXJzIGFuZCBkYXRlcywgYnV0IGl0IGRvZXMgbm90IGluY2x1ZGUgb2JqZWN0c1xuLy8gb3IgYXJyYXlzIHdpdGggZ2VuZXJpYyBzdHVmZiBpbnNpZGUuXG4vLyBSYWlzZXMgYW4gZXJyb3IgaWYgdGhpcyBjYW5ub3QgcG9zc2libHkgYmUgdmFsaWQgUkVTVCBmb3JtYXQuXG4vLyBSZXR1cm5zIENhbm5vdFRyYW5zZm9ybSBpZiBpdCdzIGp1c3Qgbm90IGFuIGF0b21cbmZ1bmN0aW9uIHRyYW5zZm9ybVRvcExldmVsQXRvbShhdG9tLCBmaWVsZCkge1xuICBzd2l0Y2ggKHR5cGVvZiBhdG9tKSB7XG4gICAgY2FzZSAnbnVtYmVyJzpcbiAgICBjYXNlICdib29sZWFuJzpcbiAgICBjYXNlICd1bmRlZmluZWQnOlxuICAgICAgcmV0dXJuIGF0b207XG4gICAgY2FzZSAnc3RyaW5nJzpcbiAgICAgIGlmIChmaWVsZCAmJiBmaWVsZC50eXBlID09PSAnUG9pbnRlcicpIHtcbiAgICAgICAgcmV0dXJuIGAke2ZpZWxkLnRhcmdldENsYXNzfSQke2F0b219YDtcbiAgICAgIH1cbiAgICAgIHJldHVybiBhdG9tO1xuICAgIGNhc2UgJ3N5bWJvbCc6XG4gICAgY2FzZSAnZnVuY3Rpb24nOlxuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgYGNhbm5vdCB0cmFuc2Zvcm0gdmFsdWU6ICR7YXRvbX1gKTtcbiAgICBjYXNlICdvYmplY3QnOlxuICAgICAgaWYgKGF0b20gaW5zdGFuY2VvZiBEYXRlKSB7XG4gICAgICAgIC8vIFRlY2huaWNhbGx5IGRhdGVzIGFyZSBub3QgcmVzdCBmb3JtYXQsIGJ1dCwgaXQgc2VlbXMgcHJldHR5XG4gICAgICAgIC8vIGNsZWFyIHdoYXQgdGhleSBzaG91bGQgYmUgdHJhbnNmb3JtZWQgdG8sIHNvIGxldCdzIGp1c3QgZG8gaXQuXG4gICAgICAgIHJldHVybiBhdG9tO1xuICAgICAgfVxuXG4gICAgICBpZiAoYXRvbSA9PT0gbnVsbCkge1xuICAgICAgICByZXR1cm4gYXRvbTtcbiAgICAgIH1cblxuICAgICAgLy8gVE9ETzogY2hlY2sgdmFsaWRpdHkgaGFyZGVyIGZvciB0aGUgX190eXBlLWRlZmluZWQgdHlwZXNcbiAgICAgIGlmIChhdG9tLl9fdHlwZSA9PSAnUG9pbnRlcicpIHtcbiAgICAgICAgcmV0dXJuIGAke2F0b20uY2xhc3NOYW1lfSQke2F0b20ub2JqZWN0SWR9YDtcbiAgICAgIH1cbiAgICAgIGlmIChEYXRlQ29kZXIuaXNWYWxpZEpTT04oYXRvbSkpIHtcbiAgICAgICAgcmV0dXJuIERhdGVDb2Rlci5KU09OVG9EYXRhYmFzZShhdG9tKTtcbiAgICAgIH1cbiAgICAgIGlmIChCeXRlc0NvZGVyLmlzVmFsaWRKU09OKGF0b20pKSB7XG4gICAgICAgIHJldHVybiBCeXRlc0NvZGVyLkpTT05Ub0RhdGFiYXNlKGF0b20pO1xuICAgICAgfVxuICAgICAgaWYgKEdlb1BvaW50Q29kZXIuaXNWYWxpZEpTT04oYXRvbSkpIHtcbiAgICAgICAgcmV0dXJuIEdlb1BvaW50Q29kZXIuSlNPTlRvRGF0YWJhc2UoYXRvbSk7XG4gICAgICB9XG4gICAgICBpZiAoUG9seWdvbkNvZGVyLmlzVmFsaWRKU09OKGF0b20pKSB7XG4gICAgICAgIHJldHVybiBQb2x5Z29uQ29kZXIuSlNPTlRvRGF0YWJhc2UoYXRvbSk7XG4gICAgICB9XG4gICAgICBpZiAoRmlsZUNvZGVyLmlzVmFsaWRKU09OKGF0b20pKSB7XG4gICAgICAgIHJldHVybiBGaWxlQ29kZXIuSlNPTlRvRGF0YWJhc2UoYXRvbSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gQ2Fubm90VHJhbnNmb3JtO1xuXG4gICAgZGVmYXVsdDpcbiAgICAgIC8vIEkgZG9uJ3QgdGhpbmsgdHlwZW9mIGNhbiBldmVyIGxldCB1cyBnZXQgaGVyZVxuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICBQYXJzZS5FcnJvci5JTlRFUk5BTF9TRVJWRVJfRVJST1IsXG4gICAgICAgIGByZWFsbHkgZGlkIG5vdCBleHBlY3QgdmFsdWU6ICR7YXRvbX1gXG4gICAgICApO1xuICB9XG59XG5cbmZ1bmN0aW9uIHJlbGF0aXZlVGltZVRvRGF0ZSh0ZXh0LCBub3cgPSBuZXcgRGF0ZSgpKSB7XG4gIHRleHQgPSB0ZXh0LnRvTG93ZXJDYXNlKCk7XG5cbiAgbGV0IHBhcnRzID0gdGV4dC5zcGxpdCgnICcpO1xuXG4gIC8vIEZpbHRlciBvdXQgd2hpdGVzcGFjZVxuICBwYXJ0cyA9IHBhcnRzLmZpbHRlcihwYXJ0ID0+IHBhcnQgIT09ICcnKTtcblxuICBjb25zdCBmdXR1cmUgPSBwYXJ0c1swXSA9PT0gJ2luJztcbiAgY29uc3QgcGFzdCA9IHBhcnRzW3BhcnRzLmxlbmd0aCAtIDFdID09PSAnYWdvJztcblxuICBpZiAoIWZ1dHVyZSAmJiAhcGFzdCAmJiB0ZXh0ICE9PSAnbm93Jykge1xuICAgIHJldHVybiB7XG4gICAgICBzdGF0dXM6ICdlcnJvcicsXG4gICAgICBpbmZvOiBcIlRpbWUgc2hvdWxkIGVpdGhlciBzdGFydCB3aXRoICdpbicgb3IgZW5kIHdpdGggJ2FnbydcIixcbiAgICB9O1xuICB9XG5cbiAgaWYgKGZ1dHVyZSAmJiBwYXN0KSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIHN0YXR1czogJ2Vycm9yJyxcbiAgICAgIGluZm86IFwiVGltZSBjYW5ub3QgaGF2ZSBib3RoICdpbicgYW5kICdhZ28nXCIsXG4gICAgfTtcbiAgfVxuXG4gIC8vIHN0cmlwIHRoZSAnYWdvJyBvciAnaW4nXG4gIGlmIChmdXR1cmUpIHtcbiAgICBwYXJ0cyA9IHBhcnRzLnNsaWNlKDEpO1xuICB9IGVsc2Uge1xuICAgIC8vIHBhc3RcbiAgICBwYXJ0cyA9IHBhcnRzLnNsaWNlKDAsIHBhcnRzLmxlbmd0aCAtIDEpO1xuICB9XG5cbiAgaWYgKHBhcnRzLmxlbmd0aCAlIDIgIT09IDAgJiYgdGV4dCAhPT0gJ25vdycpIHtcbiAgICByZXR1cm4ge1xuICAgICAgc3RhdHVzOiAnZXJyb3InLFxuICAgICAgaW5mbzogJ0ludmFsaWQgdGltZSBzdHJpbmcuIERhbmdsaW5nIHVuaXQgb3IgbnVtYmVyLicsXG4gICAgfTtcbiAgfVxuXG4gIGNvbnN0IHBhaXJzID0gW107XG4gIHdoaWxlIChwYXJ0cy5sZW5ndGgpIHtcbiAgICBwYWlycy5wdXNoKFtwYXJ0cy5zaGlmdCgpLCBwYXJ0cy5zaGlmdCgpXSk7XG4gIH1cblxuICBsZXQgc2Vjb25kcyA9IDA7XG4gIGZvciAoY29uc3QgW251bSwgaW50ZXJ2YWxdIG9mIHBhaXJzKSB7XG4gICAgY29uc3QgdmFsID0gTnVtYmVyKG51bSk7XG4gICAgaWYgKCFOdW1iZXIuaXNJbnRlZ2VyKHZhbCkpIHtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHN0YXR1czogJ2Vycm9yJyxcbiAgICAgICAgaW5mbzogYCcke251bX0nIGlzIG5vdCBhbiBpbnRlZ2VyLmAsXG4gICAgICB9O1xuICAgIH1cblxuICAgIHN3aXRjaCAoaW50ZXJ2YWwpIHtcbiAgICAgIGNhc2UgJ3lyJzpcbiAgICAgIGNhc2UgJ3lycyc6XG4gICAgICBjYXNlICd5ZWFyJzpcbiAgICAgIGNhc2UgJ3llYXJzJzpcbiAgICAgICAgc2Vjb25kcyArPSB2YWwgKiAzMTUzNjAwMDsgLy8gMzY1ICogMjQgKiA2MCAqIDYwXG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlICd3ayc6XG4gICAgICBjYXNlICd3a3MnOlxuICAgICAgY2FzZSAnd2Vlayc6XG4gICAgICBjYXNlICd3ZWVrcyc6XG4gICAgICAgIHNlY29uZHMgKz0gdmFsICogNjA0ODAwOyAvLyA3ICogMjQgKiA2MCAqIDYwXG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlICdkJzpcbiAgICAgIGNhc2UgJ2RheSc6XG4gICAgICBjYXNlICdkYXlzJzpcbiAgICAgICAgc2Vjb25kcyArPSB2YWwgKiA4NjQwMDsgLy8gMjQgKiA2MCAqIDYwXG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlICdocic6XG4gICAgICBjYXNlICdocnMnOlxuICAgICAgY2FzZSAnaG91cic6XG4gICAgICBjYXNlICdob3Vycyc6XG4gICAgICAgIHNlY29uZHMgKz0gdmFsICogMzYwMDsgLy8gNjAgKiA2MFxuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSAnbWluJzpcbiAgICAgIGNhc2UgJ21pbnMnOlxuICAgICAgY2FzZSAnbWludXRlJzpcbiAgICAgIGNhc2UgJ21pbnV0ZXMnOlxuICAgICAgICBzZWNvbmRzICs9IHZhbCAqIDYwO1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSAnc2VjJzpcbiAgICAgIGNhc2UgJ3NlY3MnOlxuICAgICAgY2FzZSAnc2Vjb25kJzpcbiAgICAgIGNhc2UgJ3NlY29uZHMnOlxuICAgICAgICBzZWNvbmRzICs9IHZhbDtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGRlZmF1bHQ6XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgc3RhdHVzOiAnZXJyb3InLFxuICAgICAgICAgIGluZm86IGBJbnZhbGlkIGludGVydmFsOiAnJHtpbnRlcnZhbH0nYCxcbiAgICAgICAgfTtcbiAgICB9XG4gIH1cblxuICBjb25zdCBtaWxsaXNlY29uZHMgPSBzZWNvbmRzICogMTAwMDtcbiAgaWYgKGZ1dHVyZSkge1xuICAgIHJldHVybiB7XG4gICAgICBzdGF0dXM6ICdzdWNjZXNzJyxcbiAgICAgIGluZm86ICdmdXR1cmUnLFxuICAgICAgcmVzdWx0OiBuZXcgRGF0ZShub3cudmFsdWVPZigpICsgbWlsbGlzZWNvbmRzKSxcbiAgICB9O1xuICB9IGVsc2UgaWYgKHBhc3QpIHtcbiAgICByZXR1cm4ge1xuICAgICAgc3RhdHVzOiAnc3VjY2VzcycsXG4gICAgICBpbmZvOiAncGFzdCcsXG4gICAgICByZXN1bHQ6IG5ldyBEYXRlKG5vdy52YWx1ZU9mKCkgLSBtaWxsaXNlY29uZHMpLFxuICAgIH07XG4gIH0gZWxzZSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIHN0YXR1czogJ3N1Y2Nlc3MnLFxuICAgICAgaW5mbzogJ3ByZXNlbnQnLFxuICAgICAgcmVzdWx0OiBuZXcgRGF0ZShub3cudmFsdWVPZigpKSxcbiAgICB9O1xuICB9XG59XG5cbi8vIFRyYW5zZm9ybXMgYSBxdWVyeSBjb25zdHJhaW50IGZyb20gUkVTVCBBUEkgZm9ybWF0IHRvIE1vbmdvIGZvcm1hdC5cbi8vIEEgY29uc3RyYWludCBpcyBzb21ldGhpbmcgd2l0aCBmaWVsZHMgbGlrZSAkbHQuXG4vLyBJZiBpdCBpcyBub3QgYSB2YWxpZCBjb25zdHJhaW50IGJ1dCBpdCBjb3VsZCBiZSBhIHZhbGlkIHNvbWV0aGluZ1xuLy8gZWxzZSwgcmV0dXJuIENhbm5vdFRyYW5zZm9ybS5cbi8vIGluQXJyYXkgaXMgd2hldGhlciB0aGlzIGlzIGFuIGFycmF5IGZpZWxkLlxuZnVuY3Rpb24gdHJhbnNmb3JtQ29uc3RyYWludChjb25zdHJhaW50LCBmaWVsZCwgY291bnQgPSBmYWxzZSkge1xuICBjb25zdCBpbkFycmF5ID0gZmllbGQgJiYgZmllbGQudHlwZSAmJiBmaWVsZC50eXBlID09PSAnQXJyYXknO1xuICBpZiAodHlwZW9mIGNvbnN0cmFpbnQgIT09ICdvYmplY3QnIHx8ICFjb25zdHJhaW50KSB7XG4gICAgcmV0dXJuIENhbm5vdFRyYW5zZm9ybTtcbiAgfVxuICBjb25zdCB0cmFuc2Zvcm1GdW5jdGlvbiA9IGluQXJyYXkgPyB0cmFuc2Zvcm1JbnRlcmlvckF0b20gOiB0cmFuc2Zvcm1Ub3BMZXZlbEF0b207XG4gIGNvbnN0IHRyYW5zZm9ybWVyID0gYXRvbSA9PiB7XG4gICAgY29uc3QgcmVzdWx0ID0gdHJhbnNmb3JtRnVuY3Rpb24oYXRvbSwgZmllbGQpO1xuICAgIGlmIChyZXN1bHQgPT09IENhbm5vdFRyYW5zZm9ybSkge1xuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgYGJhZCBhdG9tOiAke0pTT04uc3RyaW5naWZ5KGF0b20pfWApO1xuICAgIH1cbiAgICByZXR1cm4gcmVzdWx0O1xuICB9O1xuICAvLyBrZXlzIGlzIHRoZSBjb25zdHJhaW50cyBpbiByZXZlcnNlIGFscGhhYmV0aWNhbCBvcmRlci5cbiAgLy8gVGhpcyBpcyBhIGhhY2sgc28gdGhhdDpcbiAgLy8gICAkcmVnZXggaXMgaGFuZGxlZCBiZWZvcmUgJG9wdGlvbnNcbiAgLy8gICAkbmVhclNwaGVyZSBpcyBoYW5kbGVkIGJlZm9yZSAkbWF4RGlzdGFuY2VcbiAgdmFyIGtleXMgPSBPYmplY3Qua2V5cyhjb25zdHJhaW50KS5zb3J0KCkucmV2ZXJzZSgpO1xuICB2YXIgYW5zd2VyID0ge307XG4gIGZvciAodmFyIGtleSBvZiBrZXlzKSB7XG4gICAgc3dpdGNoIChrZXkpIHtcbiAgICAgIGNhc2UgJyRsdCc6XG4gICAgICBjYXNlICckbHRlJzpcbiAgICAgIGNhc2UgJyRndCc6XG4gICAgICBjYXNlICckZ3RlJzpcbiAgICAgIGNhc2UgJyRleGlzdHMnOlxuICAgICAgY2FzZSAnJG5lJzpcbiAgICAgIGNhc2UgJyRlcSc6IHtcbiAgICAgICAgY29uc3QgdmFsID0gY29uc3RyYWludFtrZXldO1xuICAgICAgICBpZiAodmFsICYmIHR5cGVvZiB2YWwgPT09ICdvYmplY3QnICYmIHZhbC4kcmVsYXRpdmVUaW1lKSB7XG4gICAgICAgICAgaWYgKGZpZWxkICYmIGZpZWxkLnR5cGUgIT09ICdEYXRlJykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sXG4gICAgICAgICAgICAgICckcmVsYXRpdmVUaW1lIGNhbiBvbmx5IGJlIHVzZWQgd2l0aCBEYXRlIGZpZWxkJ1xuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBzd2l0Y2ggKGtleSkge1xuICAgICAgICAgICAgY2FzZSAnJGV4aXN0cyc6XG4gICAgICAgICAgICBjYXNlICckbmUnOlxuICAgICAgICAgICAgY2FzZSAnJGVxJzpcbiAgICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgICAgICAgICAnJHJlbGF0aXZlVGltZSBjYW4gb25seSBiZSB1c2VkIHdpdGggdGhlICRsdCwgJGx0ZSwgJGd0LCBhbmQgJGd0ZSBvcGVyYXRvcnMnXG4gICAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgY29uc3QgcGFyc2VyUmVzdWx0ID0gcmVsYXRpdmVUaW1lVG9EYXRlKHZhbC4kcmVsYXRpdmVUaW1lKTtcbiAgICAgICAgICBpZiAocGFyc2VyUmVzdWx0LnN0YXR1cyA9PT0gJ3N1Y2Nlc3MnKSB7XG4gICAgICAgICAgICBhbnN3ZXJba2V5XSA9IHBhcnNlclJlc3VsdC5yZXN1bHQ7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBsb2cuaW5mbygnRXJyb3Igd2hpbGUgcGFyc2luZyByZWxhdGl2ZSBkYXRlJywgcGFyc2VyUmVzdWx0KTtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sXG4gICAgICAgICAgICBgYmFkICRyZWxhdGl2ZVRpbWUgKCR7a2V5fSkgdmFsdWUuICR7cGFyc2VyUmVzdWx0LmluZm99YFxuICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBhbnN3ZXJba2V5XSA9IHRyYW5zZm9ybWVyKHZhbCk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuXG4gICAgICBjYXNlICckaW4nOlxuICAgICAgY2FzZSAnJG5pbic6IHtcbiAgICAgICAgY29uc3QgYXJyID0gY29uc3RyYWludFtrZXldO1xuICAgICAgICBpZiAoIShhcnIgaW5zdGFuY2VvZiBBcnJheSkpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLCAnYmFkICcgKyBrZXkgKyAnIHZhbHVlJyk7XG4gICAgICAgIH1cbiAgICAgICAgYW5zd2VyW2tleV0gPSBfLmZsYXRNYXAoYXJyLCB2YWx1ZSA9PiB7XG4gICAgICAgICAgcmV0dXJuIChhdG9tID0+IHtcbiAgICAgICAgICAgIGlmIChBcnJheS5pc0FycmF5KGF0b20pKSB7XG4gICAgICAgICAgICAgIHJldHVybiB2YWx1ZS5tYXAodHJhbnNmb3JtZXIpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgcmV0dXJuIHRyYW5zZm9ybWVyKGF0b20pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pKHZhbHVlKTtcbiAgICAgICAgfSk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAnJGFsbCc6IHtcbiAgICAgICAgY29uc3QgYXJyID0gY29uc3RyYWludFtrZXldO1xuICAgICAgICBpZiAoIShhcnIgaW5zdGFuY2VvZiBBcnJheSkpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLCAnYmFkICcgKyBrZXkgKyAnIHZhbHVlJyk7XG4gICAgICAgIH1cbiAgICAgICAgYW5zd2VyW2tleV0gPSBhcnIubWFwKHRyYW5zZm9ybUludGVyaW9yQXRvbSk7XG5cbiAgICAgICAgY29uc3QgdmFsdWVzID0gYW5zd2VyW2tleV07XG4gICAgICAgIGlmIChpc0FueVZhbHVlUmVnZXgodmFsdWVzKSAmJiAhaXNBbGxWYWx1ZXNSZWdleE9yTm9uZSh2YWx1ZXMpKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgJ0FsbCAkYWxsIHZhbHVlcyBtdXN0IGJlIG9mIHJlZ2V4IHR5cGUgb3Igbm9uZTogJyArIHZhbHVlc1xuICAgICAgICAgICk7XG4gICAgICAgIH1cblxuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICAgIGNhc2UgJyRyZWdleCc6XG4gICAgICAgIHZhciBzID0gY29uc3RyYWludFtrZXldO1xuICAgICAgICBpZiAodHlwZW9mIHMgIT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgJ2JhZCByZWdleDogJyArIHMpO1xuICAgICAgICB9XG4gICAgICAgIGFuc3dlcltrZXldID0gcztcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgJyRjb250YWluZWRCeSc6IHtcbiAgICAgICAgY29uc3QgYXJyID0gY29uc3RyYWludFtrZXldO1xuICAgICAgICBpZiAoIShhcnIgaW5zdGFuY2VvZiBBcnJheSkpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLCBgYmFkICRjb250YWluZWRCeTogc2hvdWxkIGJlIGFuIGFycmF5YCk7XG4gICAgICAgIH1cbiAgICAgICAgYW5zd2VyLiRlbGVtTWF0Y2ggPSB7XG4gICAgICAgICAgJG5pbjogYXJyLm1hcCh0cmFuc2Zvcm1lciksXG4gICAgICAgIH07XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAnJG9wdGlvbnMnOlxuICAgICAgICBhbnN3ZXJba2V5XSA9IGNvbnN0cmFpbnRba2V5XTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgJyR0ZXh0Jzoge1xuICAgICAgICBjb25zdCBzZWFyY2ggPSBjb25zdHJhaW50W2tleV0uJHNlYXJjaDtcbiAgICAgICAgaWYgKHR5cGVvZiBzZWFyY2ggIT09ICdvYmplY3QnKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgYGJhZCAkdGV4dDogJHNlYXJjaCwgc2hvdWxkIGJlIG9iamVjdGApO1xuICAgICAgICB9XG4gICAgICAgIGlmICghc2VhcmNoLiR0ZXJtIHx8IHR5cGVvZiBzZWFyY2guJHRlcm0gIT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgYGJhZCAkdGV4dDogJHRlcm0sIHNob3VsZCBiZSBzdHJpbmdgKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBhbnN3ZXJba2V5XSA9IHtcbiAgICAgICAgICAgICRzZWFyY2g6IHNlYXJjaC4kdGVybSxcbiAgICAgICAgICB9O1xuICAgICAgICB9XG4gICAgICAgIGlmIChzZWFyY2guJGxhbmd1YWdlICYmIHR5cGVvZiBzZWFyY2guJGxhbmd1YWdlICE9PSAnc3RyaW5nJykge1xuICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sIGBiYWQgJHRleHQ6ICRsYW5ndWFnZSwgc2hvdWxkIGJlIHN0cmluZ2ApO1xuICAgICAgICB9IGVsc2UgaWYgKHNlYXJjaC4kbGFuZ3VhZ2UpIHtcbiAgICAgICAgICBhbnN3ZXJba2V5XS4kbGFuZ3VhZ2UgPSBzZWFyY2guJGxhbmd1YWdlO1xuICAgICAgICB9XG4gICAgICAgIGlmIChzZWFyY2guJGNhc2VTZW5zaXRpdmUgJiYgdHlwZW9mIHNlYXJjaC4kY2FzZVNlbnNpdGl2ZSAhPT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgYGJhZCAkdGV4dDogJGNhc2VTZW5zaXRpdmUsIHNob3VsZCBiZSBib29sZWFuYFxuICAgICAgICAgICk7XG4gICAgICAgIH0gZWxzZSBpZiAoc2VhcmNoLiRjYXNlU2Vuc2l0aXZlKSB7XG4gICAgICAgICAgYW5zd2VyW2tleV0uJGNhc2VTZW5zaXRpdmUgPSBzZWFyY2guJGNhc2VTZW5zaXRpdmU7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHNlYXJjaC4kZGlhY3JpdGljU2Vuc2l0aXZlICYmIHR5cGVvZiBzZWFyY2guJGRpYWNyaXRpY1NlbnNpdGl2ZSAhPT0gJ2Jvb2xlYW4nKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgYGJhZCAkdGV4dDogJGRpYWNyaXRpY1NlbnNpdGl2ZSwgc2hvdWxkIGJlIGJvb2xlYW5gXG4gICAgICAgICAgKTtcbiAgICAgICAgfSBlbHNlIGlmIChzZWFyY2guJGRpYWNyaXRpY1NlbnNpdGl2ZSkge1xuICAgICAgICAgIGFuc3dlcltrZXldLiRkaWFjcml0aWNTZW5zaXRpdmUgPSBzZWFyY2guJGRpYWNyaXRpY1NlbnNpdGl2ZTtcbiAgICAgICAgfVxuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICAgIGNhc2UgJyRuZWFyU3BoZXJlJzoge1xuICAgICAgICBjb25zdCBwb2ludCA9IGNvbnN0cmFpbnRba2V5XTtcbiAgICAgICAgaWYgKGNvdW50KSB7XG4gICAgICAgICAgYW5zd2VyLiRnZW9XaXRoaW4gPSB7XG4gICAgICAgICAgICAkY2VudGVyU3BoZXJlOiBbW3BvaW50LmxvbmdpdHVkZSwgcG9pbnQubGF0aXR1ZGVdLCBjb25zdHJhaW50LiRtYXhEaXN0YW5jZV0sXG4gICAgICAgICAgfTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBhbnN3ZXJba2V5XSA9IFtwb2ludC5sb25naXR1ZGUsIHBvaW50LmxhdGl0dWRlXTtcbiAgICAgICAgfVxuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICAgIGNhc2UgJyRtYXhEaXN0YW5jZSc6IHtcbiAgICAgICAgaWYgKGNvdW50KSB7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgICAgYW5zd2VyW2tleV0gPSBjb25zdHJhaW50W2tleV07XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgLy8gVGhlIFNES3MgZG9uJ3Qgc2VlbSB0byB1c2UgdGhlc2UgYnV0IHRoZXkgYXJlIGRvY3VtZW50ZWQgaW4gdGhlXG4gICAgICAvLyBSRVNUIEFQSSBkb2NzLlxuICAgICAgY2FzZSAnJG1heERpc3RhbmNlSW5SYWRpYW5zJzpcbiAgICAgICAgYW5zd2VyWyckbWF4RGlzdGFuY2UnXSA9IGNvbnN0cmFpbnRba2V5XTtcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlICckbWF4RGlzdGFuY2VJbk1pbGVzJzpcbiAgICAgICAgYW5zd2VyWyckbWF4RGlzdGFuY2UnXSA9IGNvbnN0cmFpbnRba2V5XSAvIDM5NTk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSAnJG1heERpc3RhbmNlSW5LaWxvbWV0ZXJzJzpcbiAgICAgICAgYW5zd2VyWyckbWF4RGlzdGFuY2UnXSA9IGNvbnN0cmFpbnRba2V5XSAvIDYzNzE7XG4gICAgICAgIGJyZWFrO1xuXG4gICAgICBjYXNlICckc2VsZWN0JzpcbiAgICAgIGNhc2UgJyRkb250U2VsZWN0JzpcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgIFBhcnNlLkVycm9yLkNPTU1BTkRfVU5BVkFJTEFCTEUsXG4gICAgICAgICAgJ3RoZSAnICsga2V5ICsgJyBjb25zdHJhaW50IGlzIG5vdCBzdXBwb3J0ZWQgeWV0J1xuICAgICAgICApO1xuXG4gICAgICBjYXNlICckd2l0aGluJzpcbiAgICAgICAgdmFyIGJveCA9IGNvbnN0cmFpbnRba2V5XVsnJGJveCddO1xuICAgICAgICBpZiAoIWJveCB8fCBib3gubGVuZ3RoICE9IDIpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLCAnbWFsZm9ybWF0dGVkICR3aXRoaW4gYXJnJyk7XG4gICAgICAgIH1cbiAgICAgICAgYW5zd2VyW2tleV0gPSB7XG4gICAgICAgICAgJGJveDogW1xuICAgICAgICAgICAgW2JveFswXS5sb25naXR1ZGUsIGJveFswXS5sYXRpdHVkZV0sXG4gICAgICAgICAgICBbYm94WzFdLmxvbmdpdHVkZSwgYm94WzFdLmxhdGl0dWRlXSxcbiAgICAgICAgICBdLFxuICAgICAgICB9O1xuICAgICAgICBicmVhaztcblxuICAgICAgY2FzZSAnJGdlb1dpdGhpbic6IHtcbiAgICAgICAgY29uc3QgcG9seWdvbiA9IGNvbnN0cmFpbnRba2V5XVsnJHBvbHlnb24nXTtcbiAgICAgICAgY29uc3QgY2VudGVyU3BoZXJlID0gY29uc3RyYWludFtrZXldWyckY2VudGVyU3BoZXJlJ107XG4gICAgICAgIGlmIChwb2x5Z29uICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICBsZXQgcG9pbnRzO1xuICAgICAgICAgIGlmICh0eXBlb2YgcG9seWdvbiA9PT0gJ29iamVjdCcgJiYgcG9seWdvbi5fX3R5cGUgPT09ICdQb2x5Z29uJykge1xuICAgICAgICAgICAgaWYgKCFwb2x5Z29uLmNvb3JkaW5hdGVzIHx8IHBvbHlnb24uY29vcmRpbmF0ZXMubGVuZ3RoIDwgMykge1xuICAgICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgICAgICdiYWQgJGdlb1dpdGhpbiB2YWx1ZTsgUG9seWdvbi5jb29yZGluYXRlcyBzaG91bGQgY29udGFpbiBhdCBsZWFzdCAzIGxvbi9sYXQgcGFpcnMnXG4gICAgICAgICAgICAgICk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBwb2ludHMgPSBwb2x5Z29uLmNvb3JkaW5hdGVzO1xuICAgICAgICAgIH0gZWxzZSBpZiAocG9seWdvbiBpbnN0YW5jZW9mIEFycmF5KSB7XG4gICAgICAgICAgICBpZiAocG9seWdvbi5sZW5ndGggPCAzKSB7XG4gICAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sXG4gICAgICAgICAgICAgICAgJ2JhZCAkZ2VvV2l0aGluIHZhbHVlOyAkcG9seWdvbiBzaG91bGQgY29udGFpbiBhdCBsZWFzdCAzIEdlb1BvaW50cydcbiAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHBvaW50cyA9IHBvbHlnb247XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgICBcImJhZCAkZ2VvV2l0aGluIHZhbHVlOyAkcG9seWdvbiBzaG91bGQgYmUgUG9seWdvbiBvYmplY3Qgb3IgQXJyYXkgb2YgUGFyc2UuR2VvUG9pbnQnc1wiXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH1cbiAgICAgICAgICBwb2ludHMgPSBwb2ludHMubWFwKHBvaW50ID0+IHtcbiAgICAgICAgICAgIGlmIChwb2ludCBpbnN0YW5jZW9mIEFycmF5ICYmIHBvaW50Lmxlbmd0aCA9PT0gMikge1xuICAgICAgICAgICAgICBQYXJzZS5HZW9Qb2ludC5fdmFsaWRhdGUocG9pbnRbMV0sIHBvaW50WzBdKTtcbiAgICAgICAgICAgICAgcmV0dXJuIHBvaW50O1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKCFHZW9Qb2ludENvZGVyLmlzVmFsaWRKU09OKHBvaW50KSkge1xuICAgICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLCAnYmFkICRnZW9XaXRoaW4gdmFsdWUnKTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIFBhcnNlLkdlb1BvaW50Ll92YWxpZGF0ZShwb2ludC5sYXRpdHVkZSwgcG9pbnQubG9uZ2l0dWRlKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBbcG9pbnQubG9uZ2l0dWRlLCBwb2ludC5sYXRpdHVkZV07XG4gICAgICAgICAgfSk7XG4gICAgICAgICAgYW5zd2VyW2tleV0gPSB7XG4gICAgICAgICAgICAkcG9seWdvbjogcG9pbnRzLFxuICAgICAgICAgIH07XG4gICAgICAgIH0gZWxzZSBpZiAoY2VudGVyU3BoZXJlICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICBpZiAoIShjZW50ZXJTcGhlcmUgaW5zdGFuY2VvZiBBcnJheSkgfHwgY2VudGVyU3BoZXJlLmxlbmd0aCA8IDIpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgICAnYmFkICRnZW9XaXRoaW4gdmFsdWU7ICRjZW50ZXJTcGhlcmUgc2hvdWxkIGJlIGFuIGFycmF5IG9mIFBhcnNlLkdlb1BvaW50IGFuZCBkaXN0YW5jZSdcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuICAgICAgICAgIC8vIEdldCBwb2ludCwgY29udmVydCB0byBnZW8gcG9pbnQgaWYgbmVjZXNzYXJ5IGFuZCB2YWxpZGF0ZVxuICAgICAgICAgIGxldCBwb2ludCA9IGNlbnRlclNwaGVyZVswXTtcbiAgICAgICAgICBpZiAocG9pbnQgaW5zdGFuY2VvZiBBcnJheSAmJiBwb2ludC5sZW5ndGggPT09IDIpIHtcbiAgICAgICAgICAgIHBvaW50ID0gbmV3IFBhcnNlLkdlb1BvaW50KHBvaW50WzFdLCBwb2ludFswXSk7XG4gICAgICAgICAgfSBlbHNlIGlmICghR2VvUG9pbnRDb2Rlci5pc1ZhbGlkSlNPTihwb2ludCkpIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgICAnYmFkICRnZW9XaXRoaW4gdmFsdWU7ICRjZW50ZXJTcGhlcmUgZ2VvIHBvaW50IGludmFsaWQnXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH1cbiAgICAgICAgICBQYXJzZS5HZW9Qb2ludC5fdmFsaWRhdGUocG9pbnQubGF0aXR1ZGUsIHBvaW50LmxvbmdpdHVkZSk7XG4gICAgICAgICAgLy8gR2V0IGRpc3RhbmNlIGFuZCB2YWxpZGF0ZVxuICAgICAgICAgIGNvbnN0IGRpc3RhbmNlID0gY2VudGVyU3BoZXJlWzFdO1xuICAgICAgICAgIGlmIChpc05hTihkaXN0YW5jZSkgfHwgZGlzdGFuY2UgPCAwKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgICAgICAgJ2JhZCAkZ2VvV2l0aGluIHZhbHVlOyAkY2VudGVyU3BoZXJlIGRpc3RhbmNlIGludmFsaWQnXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH1cbiAgICAgICAgICBhbnN3ZXJba2V5XSA9IHtcbiAgICAgICAgICAgICRjZW50ZXJTcGhlcmU6IFtbcG9pbnQubG9uZ2l0dWRlLCBwb2ludC5sYXRpdHVkZV0sIGRpc3RhbmNlXSxcbiAgICAgICAgICB9O1xuICAgICAgICB9XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAnJGdlb0ludGVyc2VjdHMnOiB7XG4gICAgICAgIGNvbnN0IHBvaW50ID0gY29uc3RyYWludFtrZXldWyckcG9pbnQnXTtcbiAgICAgICAgaWYgKCFHZW9Qb2ludENvZGVyLmlzVmFsaWRKU09OKHBvaW50KSkge1xuICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgICAgICdiYWQgJGdlb0ludGVyc2VjdCB2YWx1ZTsgJHBvaW50IHNob3VsZCBiZSBHZW9Qb2ludCdcbiAgICAgICAgICApO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIFBhcnNlLkdlb1BvaW50Ll92YWxpZGF0ZShwb2ludC5sYXRpdHVkZSwgcG9pbnQubG9uZ2l0dWRlKTtcbiAgICAgICAgfVxuICAgICAgICBhbnN3ZXJba2V5XSA9IHtcbiAgICAgICAgICAkZ2VvbWV0cnk6IHtcbiAgICAgICAgICAgIHR5cGU6ICdQb2ludCcsXG4gICAgICAgICAgICBjb29yZGluYXRlczogW3BvaW50LmxvbmdpdHVkZSwgcG9pbnQubGF0aXR1ZGVdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH07XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgZGVmYXVsdDpcbiAgICAgICAgaWYgKGtleS5tYXRjaCgvXlxcJCsvKSkge1xuICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sICdiYWQgY29uc3RyYWludDogJyArIGtleSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIENhbm5vdFRyYW5zZm9ybTtcbiAgICB9XG4gIH1cbiAgcmV0dXJuIGFuc3dlcjtcbn1cblxuLy8gVHJhbnNmb3JtcyBhbiB1cGRhdGUgb3BlcmF0b3IgZnJvbSBSRVNUIGZvcm1hdCB0byBtb25nbyBmb3JtYXQuXG4vLyBUbyBiZSB0cmFuc2Zvcm1lZCwgdGhlIGlucHV0IHNob3VsZCBoYXZlIGFuIF9fb3AgZmllbGQuXG4vLyBJZiBmbGF0dGVuIGlzIHRydWUsIHRoaXMgd2lsbCBmbGF0dGVuIG9wZXJhdG9ycyB0byB0aGVpciBzdGF0aWNcbi8vIGRhdGEgZm9ybWF0LiBGb3IgZXhhbXBsZSwgYW4gaW5jcmVtZW50IG9mIDIgd291bGQgc2ltcGx5IGJlY29tZSBhXG4vLyAyLlxuLy8gVGhlIG91dHB1dCBmb3IgYSBub24tZmxhdHRlbmVkIG9wZXJhdG9yIGlzIGEgaGFzaCB3aXRoIF9fb3AgYmVpbmdcbi8vIHRoZSBtb25nbyBvcCwgYW5kIGFyZyBiZWluZyB0aGUgYXJndW1lbnQuXG4vLyBUaGUgb3V0cHV0IGZvciBhIGZsYXR0ZW5lZCBvcGVyYXRvciBpcyBqdXN0IGEgdmFsdWUuXG4vLyBSZXR1cm5zIHVuZGVmaW5lZCBpZiB0aGlzIHNob3VsZCBiZSBhIG5vLW9wLlxuXG5mdW5jdGlvbiB0cmFuc2Zvcm1VcGRhdGVPcGVyYXRvcih7IF9fb3AsIGFtb3VudCwgb2JqZWN0cyB9LCBmbGF0dGVuKSB7XG4gIHN3aXRjaCAoX19vcCkge1xuICAgIGNhc2UgJ0RlbGV0ZSc6XG4gICAgICBpZiAoZmxhdHRlbikge1xuICAgICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIHsgX19vcDogJyR1bnNldCcsIGFyZzogJycgfTtcbiAgICAgIH1cblxuICAgIGNhc2UgJ0luY3JlbWVudCc6XG4gICAgICBpZiAodHlwZW9mIGFtb3VudCAhPT0gJ251bWJlcicpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgJ2luY3JlbWVudGluZyBtdXN0IHByb3ZpZGUgYSBudW1iZXInKTtcbiAgICAgIH1cbiAgICAgIGlmIChmbGF0dGVuKSB7XG4gICAgICAgIHJldHVybiBhbW91bnQ7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4geyBfX29wOiAnJGluYycsIGFyZzogYW1vdW50IH07XG4gICAgICB9XG5cbiAgICBjYXNlICdBZGQnOlxuICAgIGNhc2UgJ0FkZFVuaXF1ZSc6XG4gICAgICBpZiAoIShvYmplY3RzIGluc3RhbmNlb2YgQXJyYXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sICdvYmplY3RzIHRvIGFkZCBtdXN0IGJlIGFuIGFycmF5Jyk7XG4gICAgICB9XG4gICAgICB2YXIgdG9BZGQgPSBvYmplY3RzLm1hcCh0cmFuc2Zvcm1JbnRlcmlvckF0b20pO1xuICAgICAgaWYgKGZsYXR0ZW4pIHtcbiAgICAgICAgcmV0dXJuIHRvQWRkO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdmFyIG1vbmdvT3AgPSB7XG4gICAgICAgICAgQWRkOiAnJHB1c2gnLFxuICAgICAgICAgIEFkZFVuaXF1ZTogJyRhZGRUb1NldCcsXG4gICAgICAgIH1bX19vcF07XG4gICAgICAgIHJldHVybiB7IF9fb3A6IG1vbmdvT3AsIGFyZzogeyAkZWFjaDogdG9BZGQgfSB9O1xuICAgICAgfVxuXG4gICAgY2FzZSAnUmVtb3ZlJzpcbiAgICAgIGlmICghKG9iamVjdHMgaW5zdGFuY2VvZiBBcnJheSkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgJ29iamVjdHMgdG8gcmVtb3ZlIG11c3QgYmUgYW4gYXJyYXknKTtcbiAgICAgIH1cbiAgICAgIHZhciB0b1JlbW92ZSA9IG9iamVjdHMubWFwKHRyYW5zZm9ybUludGVyaW9yQXRvbSk7XG4gICAgICBpZiAoZmxhdHRlbikge1xuICAgICAgICByZXR1cm4gW107XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4geyBfX29wOiAnJHB1bGxBbGwnLCBhcmc6IHRvUmVtb3ZlIH07XG4gICAgICB9XG5cbiAgICBkZWZhdWx0OlxuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICBQYXJzZS5FcnJvci5DT01NQU5EX1VOQVZBSUxBQkxFLFxuICAgICAgICBgVGhlICR7X19vcH0gb3BlcmF0b3IgaXMgbm90IHN1cHBvcnRlZCB5ZXQuYFxuICAgICAgKTtcbiAgfVxufVxuZnVuY3Rpb24gbWFwVmFsdWVzKG9iamVjdCwgaXRlcmF0b3IpIHtcbiAgY29uc3QgcmVzdWx0ID0ge307XG4gIE9iamVjdC5rZXlzKG9iamVjdCkuZm9yRWFjaChrZXkgPT4ge1xuICAgIHJlc3VsdFtrZXldID0gaXRlcmF0b3Iob2JqZWN0W2tleV0pO1xuICB9KTtcbiAgcmV0dXJuIHJlc3VsdDtcbn1cblxuY29uc3QgbmVzdGVkTW9uZ29PYmplY3RUb05lc3RlZFBhcnNlT2JqZWN0ID0gbW9uZ29PYmplY3QgPT4ge1xuICBzd2l0Y2ggKHR5cGVvZiBtb25nb09iamVjdCkge1xuICAgIGNhc2UgJ3N0cmluZyc6XG4gICAgY2FzZSAnbnVtYmVyJzpcbiAgICBjYXNlICdib29sZWFuJzpcbiAgICBjYXNlICd1bmRlZmluZWQnOlxuICAgICAgcmV0dXJuIG1vbmdvT2JqZWN0O1xuICAgIGNhc2UgJ3N5bWJvbCc6XG4gICAgY2FzZSAnZnVuY3Rpb24nOlxuICAgICAgdGhyb3cgJ2JhZCB2YWx1ZSBpbiBuZXN0ZWRNb25nb09iamVjdFRvTmVzdGVkUGFyc2VPYmplY3QnO1xuICAgIGNhc2UgJ29iamVjdCc6XG4gICAgICBpZiAobW9uZ29PYmplY3QgPT09IG51bGwpIHtcbiAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICB9XG4gICAgICBpZiAobW9uZ29PYmplY3QgaW5zdGFuY2VvZiBBcnJheSkge1xuICAgICAgICByZXR1cm4gbW9uZ29PYmplY3QubWFwKG5lc3RlZE1vbmdvT2JqZWN0VG9OZXN0ZWRQYXJzZU9iamVjdCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChtb25nb09iamVjdCBpbnN0YW5jZW9mIERhdGUpIHtcbiAgICAgICAgcmV0dXJuIFBhcnNlLl9lbmNvZGUobW9uZ29PYmplY3QpO1xuICAgICAgfVxuXG4gICAgICBpZiAobW9uZ29PYmplY3QgaW5zdGFuY2VvZiBtb25nb2RiLkxvbmcpIHtcbiAgICAgICAgcmV0dXJuIG1vbmdvT2JqZWN0LnRvTnVtYmVyKCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChtb25nb09iamVjdCBpbnN0YW5jZW9mIG1vbmdvZGIuRG91YmxlKSB7XG4gICAgICAgIHJldHVybiBtb25nb09iamVjdC52YWx1ZTtcbiAgICAgIH1cblxuICAgICAgaWYgKEJ5dGVzQ29kZXIuaXNWYWxpZERhdGFiYXNlT2JqZWN0KG1vbmdvT2JqZWN0KSkge1xuICAgICAgICByZXR1cm4gQnl0ZXNDb2Rlci5kYXRhYmFzZVRvSlNPTihtb25nb09iamVjdCk7XG4gICAgICB9XG5cbiAgICAgIGlmIChcbiAgICAgICAgT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG1vbmdvT2JqZWN0LCAnX190eXBlJykgJiZcbiAgICAgICAgbW9uZ29PYmplY3QuX190eXBlID09ICdEYXRlJyAmJlxuICAgICAgICBtb25nb09iamVjdC5pc28gaW5zdGFuY2VvZiBEYXRlXG4gICAgICApIHtcbiAgICAgICAgbW9uZ29PYmplY3QuaXNvID0gbW9uZ29PYmplY3QuaXNvLnRvSlNPTigpO1xuICAgICAgICByZXR1cm4gbW9uZ29PYmplY3Q7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBtYXBWYWx1ZXMobW9uZ29PYmplY3QsIG5lc3RlZE1vbmdvT2JqZWN0VG9OZXN0ZWRQYXJzZU9iamVjdCk7XG4gICAgZGVmYXVsdDpcbiAgICAgIHRocm93ICd1bmtub3duIGpzIHR5cGUnO1xuICB9XG59O1xuXG5jb25zdCB0cmFuc2Zvcm1Qb2ludGVyU3RyaW5nID0gKHNjaGVtYSwgZmllbGQsIHBvaW50ZXJTdHJpbmcpID0+IHtcbiAgY29uc3Qgb2JqRGF0YSA9IHBvaW50ZXJTdHJpbmcuc3BsaXQoJyQnKTtcbiAgaWYgKG9iakRhdGFbMF0gIT09IHNjaGVtYS5maWVsZHNbZmllbGRdLnRhcmdldENsYXNzKSB7XG4gICAgdGhyb3cgJ3BvaW50ZXIgdG8gaW5jb3JyZWN0IGNsYXNzTmFtZSc7XG4gIH1cbiAgcmV0dXJuIHtcbiAgICBfX3R5cGU6ICdQb2ludGVyJyxcbiAgICBjbGFzc05hbWU6IG9iakRhdGFbMF0sXG4gICAgb2JqZWN0SWQ6IG9iakRhdGFbMV0sXG4gIH07XG59O1xuXG4vLyBDb252ZXJ0cyBmcm9tIGEgbW9uZ28tZm9ybWF0IG9iamVjdCB0byBhIFJFU1QtZm9ybWF0IG9iamVjdC5cbi8vIERvZXMgbm90IHN0cmlwIG91dCBhbnl0aGluZyBiYXNlZCBvbiBhIGxhY2sgb2YgYXV0aGVudGljYXRpb24uXG5jb25zdCBtb25nb09iamVjdFRvUGFyc2VPYmplY3QgPSAoY2xhc3NOYW1lLCBtb25nb09iamVjdCwgc2NoZW1hKSA9PiB7XG4gIHN3aXRjaCAodHlwZW9mIG1vbmdvT2JqZWN0KSB7XG4gICAgY2FzZSAnc3RyaW5nJzpcbiAgICBjYXNlICdudW1iZXInOlxuICAgIGNhc2UgJ2Jvb2xlYW4nOlxuICAgIGNhc2UgJ3VuZGVmaW5lZCc6XG4gICAgICByZXR1cm4gbW9uZ29PYmplY3Q7XG4gICAgY2FzZSAnc3ltYm9sJzpcbiAgICBjYXNlICdmdW5jdGlvbic6XG4gICAgICB0aHJvdyAnYmFkIHZhbHVlIGluIG1vbmdvT2JqZWN0VG9QYXJzZU9iamVjdCc7XG4gICAgY2FzZSAnb2JqZWN0Jzoge1xuICAgICAgaWYgKG1vbmdvT2JqZWN0ID09PSBudWxsKSB7XG4gICAgICAgIHJldHVybiBudWxsO1xuICAgICAgfVxuICAgICAgaWYgKG1vbmdvT2JqZWN0IGluc3RhbmNlb2YgQXJyYXkpIHtcbiAgICAgICAgcmV0dXJuIG1vbmdvT2JqZWN0Lm1hcChuZXN0ZWRNb25nb09iamVjdFRvTmVzdGVkUGFyc2VPYmplY3QpO1xuICAgICAgfVxuXG4gICAgICBpZiAobW9uZ29PYmplY3QgaW5zdGFuY2VvZiBEYXRlKSB7XG4gICAgICAgIHJldHVybiBQYXJzZS5fZW5jb2RlKG1vbmdvT2JqZWN0KTtcbiAgICAgIH1cblxuICAgICAgaWYgKG1vbmdvT2JqZWN0IGluc3RhbmNlb2YgbW9uZ29kYi5Mb25nKSB7XG4gICAgICAgIHJldHVybiBtb25nb09iamVjdC50b051bWJlcigpO1xuICAgICAgfVxuXG4gICAgICBpZiAobW9uZ29PYmplY3QgaW5zdGFuY2VvZiBtb25nb2RiLkRvdWJsZSkge1xuICAgICAgICByZXR1cm4gbW9uZ29PYmplY3QudmFsdWU7XG4gICAgICB9XG5cbiAgICAgIGlmIChCeXRlc0NvZGVyLmlzVmFsaWREYXRhYmFzZU9iamVjdChtb25nb09iamVjdCkpIHtcbiAgICAgICAgcmV0dXJuIEJ5dGVzQ29kZXIuZGF0YWJhc2VUb0pTT04obW9uZ29PYmplY3QpO1xuICAgICAgfVxuXG4gICAgICBjb25zdCByZXN0T2JqZWN0ID0ge307XG4gICAgICBpZiAobW9uZ29PYmplY3QuX3JwZXJtIHx8IG1vbmdvT2JqZWN0Ll93cGVybSkge1xuICAgICAgICByZXN0T2JqZWN0Ll9ycGVybSA9IG1vbmdvT2JqZWN0Ll9ycGVybSB8fCBbXTtcbiAgICAgICAgcmVzdE9iamVjdC5fd3Blcm0gPSBtb25nb09iamVjdC5fd3Blcm0gfHwgW107XG4gICAgICAgIGRlbGV0ZSBtb25nb09iamVjdC5fcnBlcm07XG4gICAgICAgIGRlbGV0ZSBtb25nb09iamVjdC5fd3Blcm07XG4gICAgICB9XG5cbiAgICAgIGZvciAodmFyIGtleSBpbiBtb25nb09iamVjdCkge1xuICAgICAgICBzd2l0Y2ggKGtleSkge1xuICAgICAgICAgIGNhc2UgJ19pZCc6XG4gICAgICAgICAgICByZXN0T2JqZWN0WydvYmplY3RJZCddID0gJycgKyBtb25nb09iamVjdFtrZXldO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgY2FzZSAnX2hhc2hlZF9wYXNzd29yZCc6XG4gICAgICAgICAgICByZXN0T2JqZWN0Ll9oYXNoZWRfcGFzc3dvcmQgPSBtb25nb09iamVjdFtrZXldO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgY2FzZSAnX2FjbCc6XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgICBjYXNlICdfZW1haWxfdmVyaWZ5X3Rva2VuJzpcbiAgICAgICAgICBjYXNlICdfcGVyaXNoYWJsZV90b2tlbic6XG4gICAgICAgICAgY2FzZSAnX3BlcmlzaGFibGVfdG9rZW5fZXhwaXJlc19hdCc6XG4gICAgICAgICAgY2FzZSAnX3Bhc3N3b3JkX2NoYW5nZWRfYXQnOlxuICAgICAgICAgIGNhc2UgJ190b21ic3RvbmUnOlxuICAgICAgICAgIGNhc2UgJ19lbWFpbF92ZXJpZnlfdG9rZW5fZXhwaXJlc19hdCc6XG4gICAgICAgICAgY2FzZSAnX2FjY291bnRfbG9ja291dF9leHBpcmVzX2F0JzpcbiAgICAgICAgICBjYXNlICdfZmFpbGVkX2xvZ2luX2NvdW50JzpcbiAgICAgICAgICBjYXNlICdfcGFzc3dvcmRfaGlzdG9yeSc6XG4gICAgICAgICAgICAvLyBUaG9zZSBrZXlzIHdpbGwgYmUgZGVsZXRlZCBpZiBuZWVkZWQgaW4gdGhlIERCIENvbnRyb2xsZXJcbiAgICAgICAgICAgIHJlc3RPYmplY3Rba2V5XSA9IG1vbmdvT2JqZWN0W2tleV07XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgICBjYXNlICdfc2Vzc2lvbl90b2tlbic6XG4gICAgICAgICAgICByZXN0T2JqZWN0WydzZXNzaW9uVG9rZW4nXSA9IG1vbmdvT2JqZWN0W2tleV07XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgICBjYXNlICd1cGRhdGVkQXQnOlxuICAgICAgICAgIGNhc2UgJ191cGRhdGVkX2F0JzpcbiAgICAgICAgICAgIHJlc3RPYmplY3RbJ3VwZGF0ZWRBdCddID0gUGFyc2UuX2VuY29kZShuZXcgRGF0ZShtb25nb09iamVjdFtrZXldKSkuaXNvO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgY2FzZSAnY3JlYXRlZEF0JzpcbiAgICAgICAgICBjYXNlICdfY3JlYXRlZF9hdCc6XG4gICAgICAgICAgICByZXN0T2JqZWN0WydjcmVhdGVkQXQnXSA9IFBhcnNlLl9lbmNvZGUobmV3IERhdGUobW9uZ29PYmplY3Rba2V5XSkpLmlzbztcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgIGNhc2UgJ2V4cGlyZXNBdCc6XG4gICAgICAgICAgY2FzZSAnX2V4cGlyZXNBdCc6XG4gICAgICAgICAgICByZXN0T2JqZWN0WydleHBpcmVzQXQnXSA9IFBhcnNlLl9lbmNvZGUobmV3IERhdGUobW9uZ29PYmplY3Rba2V5XSkpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgY2FzZSAnbGFzdFVzZWQnOlxuICAgICAgICAgIGNhc2UgJ19sYXN0X3VzZWQnOlxuICAgICAgICAgICAgcmVzdE9iamVjdFsnbGFzdFVzZWQnXSA9IFBhcnNlLl9lbmNvZGUobmV3IERhdGUobW9uZ29PYmplY3Rba2V5XSkpLmlzbztcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgIGNhc2UgJ3RpbWVzVXNlZCc6XG4gICAgICAgICAgY2FzZSAndGltZXNfdXNlZCc6XG4gICAgICAgICAgICByZXN0T2JqZWN0Wyd0aW1lc1VzZWQnXSA9IG1vbmdvT2JqZWN0W2tleV07XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgICBjYXNlICdhdXRoRGF0YSc6XG4gICAgICAgICAgICBpZiAoY2xhc3NOYW1lID09PSAnX1VzZXInKSB7XG4gICAgICAgICAgICAgIGxvZy53YXJuKFxuICAgICAgICAgICAgICAgICdpZ25vcmluZyBhdXRoRGF0YSBpbiBfVXNlciBhcyB0aGlzIGtleSBpcyByZXNlcnZlZCB0byBiZSBzeW50aGVzaXplZCBvZiBgX2F1dGhfZGF0YV8qYCBrZXlzJ1xuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgcmVzdE9iamVjdFsnYXV0aERhdGEnXSA9IG1vbmdvT2JqZWN0W2tleV07XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgLy8gQ2hlY2sgb3RoZXIgYXV0aCBkYXRhIGtleXNcbiAgICAgICAgICAgIHZhciBhdXRoRGF0YU1hdGNoID0ga2V5Lm1hdGNoKC9eX2F1dGhfZGF0YV8oW2EtekEtWjAtOV9dKykkLyk7XG4gICAgICAgICAgICBpZiAoYXV0aERhdGFNYXRjaCAmJiBjbGFzc05hbWUgPT09ICdfVXNlcicpIHtcbiAgICAgICAgICAgICAgdmFyIHByb3ZpZGVyID0gYXV0aERhdGFNYXRjaFsxXTtcbiAgICAgICAgICAgICAgcmVzdE9iamVjdFsnYXV0aERhdGEnXSA9IHJlc3RPYmplY3RbJ2F1dGhEYXRhJ10gfHwge307XG4gICAgICAgICAgICAgIHJlc3RPYmplY3RbJ2F1dGhEYXRhJ11bcHJvdmlkZXJdID0gbW9uZ29PYmplY3Rba2V5XTtcbiAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmIChrZXkuaW5kZXhPZignX3BfJykgPT0gMCkge1xuICAgICAgICAgICAgICB2YXIgbmV3S2V5ID0ga2V5LnN1YnN0cmluZygzKTtcbiAgICAgICAgICAgICAgaWYgKCFzY2hlbWEuZmllbGRzW25ld0tleV0pIHtcbiAgICAgICAgICAgICAgICBsb2cuaW5mbyhcbiAgICAgICAgICAgICAgICAgICd0cmFuc2Zvcm0uanMnLFxuICAgICAgICAgICAgICAgICAgJ0ZvdW5kIGEgcG9pbnRlciBjb2x1bW4gbm90IGluIHRoZSBzY2hlbWEsIGRyb3BwaW5nIGl0LicsXG4gICAgICAgICAgICAgICAgICBjbGFzc05hbWUsXG4gICAgICAgICAgICAgICAgICBuZXdLZXlcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGlmIChzY2hlbWEuZmllbGRzW25ld0tleV0udHlwZSAhPT0gJ1BvaW50ZXInKSB7XG4gICAgICAgICAgICAgICAgbG9nLmluZm8oXG4gICAgICAgICAgICAgICAgICAndHJhbnNmb3JtLmpzJyxcbiAgICAgICAgICAgICAgICAgICdGb3VuZCBhIHBvaW50ZXIgaW4gYSBub24tcG9pbnRlciBjb2x1bW4sIGRyb3BwaW5nIGl0LicsXG4gICAgICAgICAgICAgICAgICBjbGFzc05hbWUsXG4gICAgICAgICAgICAgICAgICBrZXlcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGlmIChtb25nb09iamVjdFtrZXldID09PSBudWxsKSB7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgcmVzdE9iamVjdFtuZXdLZXldID0gdHJhbnNmb3JtUG9pbnRlclN0cmluZyhzY2hlbWEsIG5ld0tleSwgbW9uZ29PYmplY3Rba2V5XSk7XG4gICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgfSBlbHNlIGlmIChrZXlbMF0gPT0gJ18nICYmIGtleSAhPSAnX190eXBlJykge1xuICAgICAgICAgICAgICB0aHJvdyAnYmFkIGtleSBpbiB1bnRyYW5zZm9ybTogJyArIGtleTtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIHZhciB2YWx1ZSA9IG1vbmdvT2JqZWN0W2tleV07XG4gICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICBzY2hlbWEuZmllbGRzW2tleV0gJiZcbiAgICAgICAgICAgICAgICBzY2hlbWEuZmllbGRzW2tleV0udHlwZSA9PT0gJ0ZpbGUnICYmXG4gICAgICAgICAgICAgICAgRmlsZUNvZGVyLmlzVmFsaWREYXRhYmFzZU9iamVjdCh2YWx1ZSlcbiAgICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgICAgcmVzdE9iamVjdFtrZXldID0gRmlsZUNvZGVyLmRhdGFiYXNlVG9KU09OKHZhbHVlKTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAgICAgc2NoZW1hLmZpZWxkc1trZXldICYmXG4gICAgICAgICAgICAgICAgc2NoZW1hLmZpZWxkc1trZXldLnR5cGUgPT09ICdHZW9Qb2ludCcgJiZcbiAgICAgICAgICAgICAgICBHZW9Qb2ludENvZGVyLmlzVmFsaWREYXRhYmFzZU9iamVjdCh2YWx1ZSlcbiAgICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgICAgcmVzdE9iamVjdFtrZXldID0gR2VvUG9pbnRDb2Rlci5kYXRhYmFzZVRvSlNPTih2YWx1ZSk7XG4gICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgaWYgKFxuICAgICAgICAgICAgICAgIHNjaGVtYS5maWVsZHNba2V5XSAmJlxuICAgICAgICAgICAgICAgIHNjaGVtYS5maWVsZHNba2V5XS50eXBlID09PSAnUG9seWdvbicgJiZcbiAgICAgICAgICAgICAgICBQb2x5Z29uQ29kZXIuaXNWYWxpZERhdGFiYXNlT2JqZWN0KHZhbHVlKVxuICAgICAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgICByZXN0T2JqZWN0W2tleV0gPSBQb2x5Z29uQ29kZXIuZGF0YWJhc2VUb0pTT04odmFsdWUpO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICBzY2hlbWEuZmllbGRzW2tleV0gJiZcbiAgICAgICAgICAgICAgICBzY2hlbWEuZmllbGRzW2tleV0udHlwZSA9PT0gJ0J5dGVzJyAmJlxuICAgICAgICAgICAgICAgIEJ5dGVzQ29kZXIuaXNWYWxpZERhdGFiYXNlT2JqZWN0KHZhbHVlKVxuICAgICAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgICByZXN0T2JqZWN0W2tleV0gPSBCeXRlc0NvZGVyLmRhdGFiYXNlVG9KU09OKHZhbHVlKTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmVzdE9iamVjdFtrZXldID0gbmVzdGVkTW9uZ29PYmplY3RUb05lc3RlZFBhcnNlT2JqZWN0KG1vbmdvT2JqZWN0W2tleV0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IHJlbGF0aW9uRmllbGROYW1lcyA9IE9iamVjdC5rZXlzKHNjaGVtYS5maWVsZHMpLmZpbHRlcihcbiAgICAgICAgZmllbGROYW1lID0+IHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS50eXBlID09PSAnUmVsYXRpb24nXG4gICAgICApO1xuICAgICAgY29uc3QgcmVsYXRpb25GaWVsZHMgPSB7fTtcbiAgICAgIHJlbGF0aW9uRmllbGROYW1lcy5mb3JFYWNoKHJlbGF0aW9uRmllbGROYW1lID0+IHtcbiAgICAgICAgcmVsYXRpb25GaWVsZHNbcmVsYXRpb25GaWVsZE5hbWVdID0ge1xuICAgICAgICAgIF9fdHlwZTogJ1JlbGF0aW9uJyxcbiAgICAgICAgICBjbGFzc05hbWU6IHNjaGVtYS5maWVsZHNbcmVsYXRpb25GaWVsZE5hbWVdLnRhcmdldENsYXNzLFxuICAgICAgICB9O1xuICAgICAgfSk7XG5cbiAgICAgIHJldHVybiB7IC4uLnJlc3RPYmplY3QsIC4uLnJlbGF0aW9uRmllbGRzIH07XG4gICAgfVxuICAgIGRlZmF1bHQ6XG4gICAgICB0aHJvdyAndW5rbm93biBqcyB0eXBlJztcbiAgfVxufTtcblxudmFyIERhdGVDb2RlciA9IHtcbiAgSlNPTlRvRGF0YWJhc2UoanNvbikge1xuICAgIHJldHVybiBuZXcgRGF0ZShqc29uLmlzbyk7XG4gIH0sXG5cbiAgaXNWYWxpZEpTT04odmFsdWUpIHtcbiAgICByZXR1cm4gdHlwZW9mIHZhbHVlID09PSAnb2JqZWN0JyAmJiB2YWx1ZSAhPT0gbnVsbCAmJiB2YWx1ZS5fX3R5cGUgPT09ICdEYXRlJztcbiAgfSxcbn07XG5cbnZhciBCeXRlc0NvZGVyID0ge1xuICBiYXNlNjRQYXR0ZXJuOiBuZXcgUmVnRXhwKCdeKD86W0EtWmEtejAtOSsvXXs0fSkqKD86W0EtWmEtejAtOSsvXXsyfT09fFtBLVphLXowLTkrL117M309KT8kJyksXG4gIGlzQmFzZTY0VmFsdWUob2JqZWN0KSB7XG4gICAgaWYgKHR5cGVvZiBvYmplY3QgIT09ICdzdHJpbmcnKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLmJhc2U2NFBhdHRlcm4udGVzdChvYmplY3QpO1xuICB9LFxuXG4gIGRhdGFiYXNlVG9KU09OKG9iamVjdCkge1xuICAgIGxldCB2YWx1ZTtcbiAgICBpZiAodGhpcy5pc0Jhc2U2NFZhbHVlKG9iamVjdCkpIHtcbiAgICAgIHZhbHVlID0gb2JqZWN0O1xuICAgIH0gZWxzZSB7XG4gICAgICB2YWx1ZSA9IG9iamVjdC5idWZmZXIudG9TdHJpbmcoJ2Jhc2U2NCcpO1xuICAgIH1cbiAgICByZXR1cm4ge1xuICAgICAgX190eXBlOiAnQnl0ZXMnLFxuICAgICAgYmFzZTY0OiB2YWx1ZSxcbiAgICB9O1xuICB9LFxuXG4gIGlzVmFsaWREYXRhYmFzZU9iamVjdChvYmplY3QpIHtcbiAgICByZXR1cm4gb2JqZWN0IGluc3RhbmNlb2YgbW9uZ29kYi5CaW5hcnkgfHwgdGhpcy5pc0Jhc2U2NFZhbHVlKG9iamVjdCk7XG4gIH0sXG5cbiAgSlNPTlRvRGF0YWJhc2UoanNvbikge1xuICAgIHJldHVybiBuZXcgbW9uZ29kYi5CaW5hcnkoQnVmZmVyLmZyb20oanNvbi5iYXNlNjQsICdiYXNlNjQnKSk7XG4gIH0sXG5cbiAgaXNWYWxpZEpTT04odmFsdWUpIHtcbiAgICByZXR1cm4gdHlwZW9mIHZhbHVlID09PSAnb2JqZWN0JyAmJiB2YWx1ZSAhPT0gbnVsbCAmJiB2YWx1ZS5fX3R5cGUgPT09ICdCeXRlcyc7XG4gIH0sXG59O1xuXG52YXIgR2VvUG9pbnRDb2RlciA9IHtcbiAgZGF0YWJhc2VUb0pTT04ob2JqZWN0KSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIF9fdHlwZTogJ0dlb1BvaW50JyxcbiAgICAgIGxhdGl0dWRlOiBvYmplY3RbMV0sXG4gICAgICBsb25naXR1ZGU6IG9iamVjdFswXSxcbiAgICB9O1xuICB9LFxuXG4gIGlzVmFsaWREYXRhYmFzZU9iamVjdChvYmplY3QpIHtcbiAgICByZXR1cm4gb2JqZWN0IGluc3RhbmNlb2YgQXJyYXkgJiYgb2JqZWN0Lmxlbmd0aCA9PSAyO1xuICB9LFxuXG4gIEpTT05Ub0RhdGFiYXNlKGpzb24pIHtcbiAgICByZXR1cm4gW2pzb24ubG9uZ2l0dWRlLCBqc29uLmxhdGl0dWRlXTtcbiAgfSxcblxuICBpc1ZhbGlkSlNPTih2YWx1ZSkge1xuICAgIHJldHVybiB0eXBlb2YgdmFsdWUgPT09ICdvYmplY3QnICYmIHZhbHVlICE9PSBudWxsICYmIHZhbHVlLl9fdHlwZSA9PT0gJ0dlb1BvaW50JztcbiAgfSxcbn07XG5cbnZhciBQb2x5Z29uQ29kZXIgPSB7XG4gIGRhdGFiYXNlVG9KU09OKG9iamVjdCkge1xuICAgIC8vIENvbnZlcnQgbG5nL2xhdCAtPiBsYXQvbG5nXG4gICAgY29uc3QgY29vcmRzID0gb2JqZWN0LmNvb3JkaW5hdGVzWzBdLm1hcChjb29yZCA9PiB7XG4gICAgICByZXR1cm4gW2Nvb3JkWzFdLCBjb29yZFswXV07XG4gICAgfSk7XG4gICAgcmV0dXJuIHtcbiAgICAgIF9fdHlwZTogJ1BvbHlnb24nLFxuICAgICAgY29vcmRpbmF0ZXM6IGNvb3JkcyxcbiAgICB9O1xuICB9LFxuXG4gIGlzVmFsaWREYXRhYmFzZU9iamVjdChvYmplY3QpIHtcbiAgICBjb25zdCBjb29yZHMgPSBvYmplY3QuY29vcmRpbmF0ZXNbMF07XG4gICAgaWYgKG9iamVjdC50eXBlICE9PSAnUG9seWdvbicgfHwgIShjb29yZHMgaW5zdGFuY2VvZiBBcnJheSkpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBjb29yZHMubGVuZ3RoOyBpKyspIHtcbiAgICAgIGNvbnN0IHBvaW50ID0gY29vcmRzW2ldO1xuICAgICAgaWYgKCFHZW9Qb2ludENvZGVyLmlzVmFsaWREYXRhYmFzZU9iamVjdChwb2ludCkpIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfVxuICAgICAgUGFyc2UuR2VvUG9pbnQuX3ZhbGlkYXRlKHBhcnNlRmxvYXQocG9pbnRbMV0pLCBwYXJzZUZsb2F0KHBvaW50WzBdKSk7XG4gICAgfVxuICAgIHJldHVybiB0cnVlO1xuICB9LFxuXG4gIEpTT05Ub0RhdGFiYXNlKGpzb24pIHtcbiAgICBsZXQgY29vcmRzID0ganNvbi5jb29yZGluYXRlcztcbiAgICAvLyBBZGQgZmlyc3QgcG9pbnQgdG8gdGhlIGVuZCB0byBjbG9zZSBwb2x5Z29uXG4gICAgaWYgKFxuICAgICAgY29vcmRzWzBdWzBdICE9PSBjb29yZHNbY29vcmRzLmxlbmd0aCAtIDFdWzBdIHx8XG4gICAgICBjb29yZHNbMF1bMV0gIT09IGNvb3Jkc1tjb29yZHMubGVuZ3RoIC0gMV1bMV1cbiAgICApIHtcbiAgICAgIGNvb3Jkcy5wdXNoKGNvb3Jkc1swXSk7XG4gICAgfVxuICAgIGNvbnN0IHVuaXF1ZSA9IGNvb3Jkcy5maWx0ZXIoKGl0ZW0sIGluZGV4LCBhcikgPT4ge1xuICAgICAgbGV0IGZvdW5kSW5kZXggPSAtMTtcbiAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgYXIubGVuZ3RoOyBpICs9IDEpIHtcbiAgICAgICAgY29uc3QgcHQgPSBhcltpXTtcbiAgICAgICAgaWYgKHB0WzBdID09PSBpdGVtWzBdICYmIHB0WzFdID09PSBpdGVtWzFdKSB7XG4gICAgICAgICAgZm91bmRJbmRleCA9IGk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiBmb3VuZEluZGV4ID09PSBpbmRleDtcbiAgICB9KTtcbiAgICBpZiAodW5pcXVlLmxlbmd0aCA8IDMpIHtcbiAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgUGFyc2UuRXJyb3IuSU5URVJOQUxfU0VSVkVSX0VSUk9SLFxuICAgICAgICAnR2VvSlNPTjogTG9vcCBtdXN0IGhhdmUgYXQgbGVhc3QgMyBkaWZmZXJlbnQgdmVydGljZXMnXG4gICAgICApO1xuICAgIH1cbiAgICAvLyBDb252ZXJ0IGxhdC9sb25nIC0+IGxvbmcvbGF0XG4gICAgY29vcmRzID0gY29vcmRzLm1hcChjb29yZCA9PiB7XG4gICAgICByZXR1cm4gW2Nvb3JkWzFdLCBjb29yZFswXV07XG4gICAgfSk7XG4gICAgcmV0dXJuIHsgdHlwZTogJ1BvbHlnb24nLCBjb29yZGluYXRlczogW2Nvb3Jkc10gfTtcbiAgfSxcblxuICBpc1ZhbGlkSlNPTih2YWx1ZSkge1xuICAgIHJldHVybiB0eXBlb2YgdmFsdWUgPT09ICdvYmplY3QnICYmIHZhbHVlICE9PSBudWxsICYmIHZhbHVlLl9fdHlwZSA9PT0gJ1BvbHlnb24nO1xuICB9LFxufTtcblxudmFyIEZpbGVDb2RlciA9IHtcbiAgZGF0YWJhc2VUb0pTT04ob2JqZWN0KSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIF9fdHlwZTogJ0ZpbGUnLFxuICAgICAgbmFtZTogb2JqZWN0LFxuICAgIH07XG4gIH0sXG5cbiAgaXNWYWxpZERhdGFiYXNlT2JqZWN0KG9iamVjdCkge1xuICAgIHJldHVybiB0eXBlb2Ygb2JqZWN0ID09PSAnc3RyaW5nJztcbiAgfSxcblxuICBKU09OVG9EYXRhYmFzZShqc29uKSB7XG4gICAgcmV0dXJuIGpzb24ubmFtZTtcbiAgfSxcblxuICBpc1ZhbGlkSlNPTih2YWx1ZSkge1xuICAgIHJldHVybiB0eXBlb2YgdmFsdWUgPT09ICdvYmplY3QnICYmIHZhbHVlICE9PSBudWxsICYmIHZhbHVlLl9fdHlwZSA9PT0gJ0ZpbGUnO1xuICB9LFxufTtcblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gIHRyYW5zZm9ybUtleSxcbiAgcGFyc2VPYmplY3RUb01vbmdvT2JqZWN0Rm9yQ3JlYXRlLFxuICB0cmFuc2Zvcm1VcGRhdGUsXG4gIHRyYW5zZm9ybVdoZXJlLFxuICBtb25nb09iamVjdFRvUGFyc2VPYmplY3QsXG4gIHJlbGF0aXZlVGltZVRvRGF0ZSxcbiAgdHJhbnNmb3JtQ29uc3RyYWludCxcbiAgdHJhbnNmb3JtUG9pbnRlclN0cmluZyxcbn07XG4iXX0=