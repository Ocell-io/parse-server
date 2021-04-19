"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = exports.PostgresStorageAdapter = void 0;

var _PostgresClient = require("./PostgresClient");

var _node = _interopRequireDefault(require("parse/node"));

var _lodash = _interopRequireDefault(require("lodash"));

var _uuid = require("uuid");

var _sql = _interopRequireDefault(require("./sql"));

var _StorageAdapter = require("../StorageAdapter");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

const PostgresRelationDoesNotExistError = '42P01';
const PostgresDuplicateRelationError = '42P07';
const PostgresDuplicateColumnError = '42701';
const PostgresMissingColumnError = '42703';
const PostgresDuplicateObjectError = '42710';
const PostgresUniqueIndexViolationError = '23505';

const logger = require('../../../logger');

const debug = function (...args) {
  args = ['PG: ' + arguments[0]].concat(args.slice(1, args.length));
  const log = logger.getLogger();
  log.debug.apply(log, args);
};

const parseTypeToPostgresType = type => {
  switch (type.type) {
    case 'String':
      return 'text';

    case 'Date':
      return 'timestamp with time zone';

    case 'Object':
      return 'jsonb';

    case 'File':
      return 'text';

    case 'Boolean':
      return 'boolean';

    case 'Pointer':
      return 'text';

    case 'Number':
      return 'double precision';

    case 'GeoPoint':
      return 'point';

    case 'Bytes':
      return 'jsonb';

    case 'Polygon':
      return 'polygon';

    case 'Array':
      if (type.contents && type.contents.type === 'String') {
        return 'text[]';
      } else {
        return 'jsonb';
      }

    default:
      throw `no type for ${JSON.stringify(type)} yet`;
  }
};

const ParseToPosgresComparator = {
  $gt: '>',
  $lt: '<',
  $gte: '>=',
  $lte: '<='
};
const mongoAggregateToPostgres = {
  $dayOfMonth: 'DAY',
  $dayOfWeek: 'DOW',
  $dayOfYear: 'DOY',
  $isoDayOfWeek: 'ISODOW',
  $isoWeekYear: 'ISOYEAR',
  $hour: 'HOUR',
  $minute: 'MINUTE',
  $second: 'SECOND',
  $millisecond: 'MILLISECONDS',
  $month: 'MONTH',
  $week: 'WEEK',
  $year: 'YEAR'
};

const toPostgresValue = value => {
  if (typeof value === 'object') {
    if (value.__type === 'Date') {
      return value.iso;
    }

    if (value.__type === 'File') {
      return value.name;
    }
  }

  return value;
};

const transformValue = value => {
  if (typeof value === 'object' && value.__type === 'Pointer') {
    return value.objectId;
  }

  return value;
}; // Duplicate from then mongo adapter...


const emptyCLPS = Object.freeze({
  find: {},
  get: {},
  count: {},
  create: {},
  update: {},
  delete: {},
  addField: {},
  protectedFields: {}
});
const defaultCLPS = Object.freeze({
  find: {
    '*': true
  },
  get: {
    '*': true
  },
  count: {
    '*': true
  },
  create: {
    '*': true
  },
  update: {
    '*': true
  },
  delete: {
    '*': true
  },
  addField: {
    '*': true
  },
  protectedFields: {
    '*': []
  }
});

const toParseSchema = schema => {
  if (schema.className === '_User') {
    delete schema.fields._hashed_password;
  }

  if (schema.fields) {
    delete schema.fields._wperm;
    delete schema.fields._rperm;
  }

  let clps = defaultCLPS;

  if (schema.classLevelPermissions) {
    clps = _objectSpread(_objectSpread({}, emptyCLPS), schema.classLevelPermissions);
  }

  let indexes = {};

  if (schema.indexes) {
    indexes = _objectSpread({}, schema.indexes);
  }

  return {
    className: schema.className,
    fields: schema.fields,
    classLevelPermissions: clps,
    indexes
  };
};

const toPostgresSchema = schema => {
  if (!schema) {
    return schema;
  }

  schema.fields = schema.fields || {};
  schema.fields._wperm = {
    type: 'Array',
    contents: {
      type: 'String'
    }
  };
  schema.fields._rperm = {
    type: 'Array',
    contents: {
      type: 'String'
    }
  };

  if (schema.className === '_User') {
    schema.fields._hashed_password = {
      type: 'String'
    };
    schema.fields._password_history = {
      type: 'Array'
    };
  }

  return schema;
};

const handleDotFields = object => {
  Object.keys(object).forEach(fieldName => {
    if (fieldName.indexOf('.') > -1) {
      const components = fieldName.split('.');
      const first = components.shift();
      object[first] = object[first] || {};
      let currentObj = object[first];
      let next;
      let value = object[fieldName];

      if (value && value.__op === 'Delete') {
        value = undefined;
      }
      /* eslint-disable no-cond-assign */


      while (next = components.shift()) {
        /* eslint-enable no-cond-assign */
        currentObj[next] = currentObj[next] || {};

        if (components.length === 0) {
          currentObj[next] = value;
        }

        currentObj = currentObj[next];
      }

      delete object[fieldName];
    }
  });
  return object;
};

const transformDotFieldToComponents = fieldName => {
  return fieldName.split('.').map((cmpt, index) => {
    if (index === 0) {
      return `"${cmpt}"`;
    }

    return `'${cmpt}'`;
  });
};

const transformDotField = fieldName => {
  if (fieldName.indexOf('.') === -1) {
    return `"${fieldName}"`;
  }

  const components = transformDotFieldToComponents(fieldName);
  let name = components.slice(0, components.length - 1).join('->');
  name += '->>' + components[components.length - 1];
  return name;
};

const transformAggregateField = fieldName => {
  if (typeof fieldName !== 'string') {
    return fieldName;
  }

  if (fieldName === '$_created_at') {
    return 'createdAt';
  }

  if (fieldName === '$_updated_at') {
    return 'updatedAt';
  }

  return fieldName.substr(1);
};

const validateKeys = object => {
  if (typeof object == 'object') {
    for (const key in object) {
      if (typeof object[key] == 'object') {
        validateKeys(object[key]);
      }

      if (key.includes('$') || key.includes('.')) {
        throw new _node.default.Error(_node.default.Error.INVALID_NESTED_KEY, "Nested keys should not contain the '$' or '.' characters");
      }
    }
  }
}; // Returns the list of join tables on a schema


const joinTablesForSchema = schema => {
  const list = [];

  if (schema) {
    Object.keys(schema.fields).forEach(field => {
      if (schema.fields[field].type === 'Relation') {
        list.push(`_Join:${field}:${schema.className}`);
      }
    });
  }

  return list;
};

const buildWhereClause = ({
  schema,
  query,
  index,
  caseInsensitive
}) => {
  const patterns = [];
  let values = [];
  const sorts = [];
  schema = toPostgresSchema(schema);

  for (const fieldName in query) {
    const isArrayField = schema.fields && schema.fields[fieldName] && schema.fields[fieldName].type === 'Array';
    const initialPatternsLength = patterns.length;
    const fieldValue = query[fieldName]; // nothing in the schema, it's gonna blow up

    if (!schema.fields[fieldName]) {
      // as it won't exist
      if (fieldValue && fieldValue.$exists === false) {
        continue;
      }
    }

    const authDataMatch = fieldName.match(/^_auth_data_([a-zA-Z0-9_]+)$/);

    if (authDataMatch) {
      // TODO: Handle querying by _auth_data_provider, authData is stored in authData field
      continue;
    } else if (caseInsensitive && (fieldName === 'username' || fieldName === 'email')) {
      patterns.push(`LOWER($${index}:name) = LOWER($${index + 1})`);
      values.push(fieldName, fieldValue);
      index += 2;
    } else if (fieldName.indexOf('.') >= 0) {
      let name = transformDotField(fieldName);

      if (fieldValue === null) {
        patterns.push(`$${index}:raw IS NULL`);
        values.push(name);
        index += 1;
        continue;
      } else {
        if (fieldValue.$in) {
          name = transformDotFieldToComponents(fieldName).join('->');
          patterns.push(`($${index}:raw)::jsonb @> $${index + 1}::jsonb`);
          values.push(name, JSON.stringify(fieldValue.$in));
          index += 2;
        } else if (fieldValue.$regex) {// Handle later
        } else if (typeof fieldValue !== 'object') {
          patterns.push(`$${index}:raw = $${index + 1}::text`);
          values.push(name, fieldValue);
          index += 2;
        }
      }
    } else if (fieldValue === null || fieldValue === undefined) {
      patterns.push(`$${index}:name IS NULL`);
      values.push(fieldName);
      index += 1;
      continue;
    } else if (typeof fieldValue === 'string') {
      patterns.push(`$${index}:name = $${index + 1}`);
      values.push(fieldName, fieldValue);
      index += 2;
    } else if (typeof fieldValue === 'boolean') {
      patterns.push(`$${index}:name = $${index + 1}`); // Can't cast boolean to double precision

      if (schema.fields[fieldName] && schema.fields[fieldName].type === 'Number') {
        // Should always return zero results
        const MAX_INT_PLUS_ONE = 9223372036854775808;
        values.push(fieldName, MAX_INT_PLUS_ONE);
      } else {
        values.push(fieldName, fieldValue);
      }

      index += 2;
    } else if (typeof fieldValue === 'number') {
      patterns.push(`$${index}:name = $${index + 1}`);
      values.push(fieldName, fieldValue);
      index += 2;
    } else if (['$or', '$nor', '$and'].includes(fieldName)) {
      const clauses = [];
      const clauseValues = [];
      fieldValue.forEach(subQuery => {
        const clause = buildWhereClause({
          schema,
          query: subQuery,
          index,
          caseInsensitive
        });

        if (clause.pattern.length > 0) {
          clauses.push(clause.pattern);
          clauseValues.push(...clause.values);
          index += clause.values.length;
        }
      });
      const orOrAnd = fieldName === '$and' ? ' AND ' : ' OR ';
      const not = fieldName === '$nor' ? ' NOT ' : '';
      patterns.push(`${not}(${clauses.join(orOrAnd)})`);
      values.push(...clauseValues);
    }

    if (fieldValue.$ne !== undefined) {
      if (isArrayField) {
        fieldValue.$ne = JSON.stringify([fieldValue.$ne]);
        patterns.push(`NOT array_contains($${index}:name, $${index + 1})`);
      } else {
        if (fieldValue.$ne === null) {
          patterns.push(`$${index}:name IS NOT NULL`);
          values.push(fieldName);
          index += 1;
          continue;
        } else {
          // if not null, we need to manually exclude null
          if (fieldValue.$ne.__type === 'GeoPoint') {
            patterns.push(`($${index}:name <> POINT($${index + 1}, $${index + 2}) OR $${index}:name IS NULL)`);
          } else {
            if (fieldName.indexOf('.') >= 0) {
              const constraintFieldName = transformDotField(fieldName);
              patterns.push(`(${constraintFieldName} <> $${index} OR ${constraintFieldName} IS NULL)`);
            } else {
              patterns.push(`($${index}:name <> $${index + 1} OR $${index}:name IS NULL)`);
            }
          }
        }
      }

      if (fieldValue.$ne.__type === 'GeoPoint') {
        const point = fieldValue.$ne;
        values.push(fieldName, point.longitude, point.latitude);
        index += 3;
      } else {
        // TODO: support arrays
        values.push(fieldName, fieldValue.$ne);
        index += 2;
      }
    }

    if (fieldValue.$eq !== undefined) {
      if (fieldValue.$eq === null) {
        patterns.push(`$${index}:name IS NULL`);
        values.push(fieldName);
        index += 1;
      } else {
        if (fieldName.indexOf('.') >= 0) {
          values.push(fieldValue.$eq);
          patterns.push(`${transformDotField(fieldName)} = $${index++}`);
        } else {
          values.push(fieldName, fieldValue.$eq);
          patterns.push(`$${index}:name = $${index + 1}`);
          index += 2;
        }
      }
    }

    const isInOrNin = Array.isArray(fieldValue.$in) || Array.isArray(fieldValue.$nin);

    if (Array.isArray(fieldValue.$in) && isArrayField && schema.fields[fieldName].contents && schema.fields[fieldName].contents.type === 'String') {
      const inPatterns = [];
      let allowNull = false;
      values.push(fieldName);
      fieldValue.$in.forEach((listElem, listIndex) => {
        if (listElem === null) {
          allowNull = true;
        } else {
          values.push(listElem);
          inPatterns.push(`$${index + 1 + listIndex - (allowNull ? 1 : 0)}`);
        }
      });

      if (allowNull) {
        patterns.push(`($${index}:name IS NULL OR $${index}:name && ARRAY[${inPatterns.join()}])`);
      } else {
        patterns.push(`$${index}:name && ARRAY[${inPatterns.join()}]`);
      }

      index = index + 1 + inPatterns.length;
    } else if (isInOrNin) {
      var createConstraint = (baseArray, notIn) => {
        const not = notIn ? ' NOT ' : '';

        if (baseArray.length > 0) {
          if (isArrayField) {
            patterns.push(`${not} array_contains($${index}:name, $${index + 1})`);
            values.push(fieldName, JSON.stringify(baseArray));
            index += 2;
          } else {
            // Handle Nested Dot Notation Above
            if (fieldName.indexOf('.') >= 0) {
              return;
            }

            const inPatterns = [];
            values.push(fieldName);
            baseArray.forEach((listElem, listIndex) => {
              if (listElem != null) {
                values.push(listElem);
                inPatterns.push(`$${index + 1 + listIndex}`);
              }
            });
            patterns.push(`$${index}:name ${not} IN (${inPatterns.join()})`);
            index = index + 1 + inPatterns.length;
          }
        } else if (!notIn) {
          values.push(fieldName);
          patterns.push(`$${index}:name IS NULL`);
          index = index + 1;
        } else {
          // Handle empty array
          if (notIn) {
            patterns.push('1 = 1'); // Return all values
          } else {
            patterns.push('1 = 2'); // Return no values
          }
        }
      };

      if (fieldValue.$in) {
        createConstraint(_lodash.default.flatMap(fieldValue.$in, elt => elt), false);
      }

      if (fieldValue.$nin) {
        createConstraint(_lodash.default.flatMap(fieldValue.$nin, elt => elt), true);
      }
    } else if (typeof fieldValue.$in !== 'undefined') {
      throw new _node.default.Error(_node.default.Error.INVALID_JSON, 'bad $in value');
    } else if (typeof fieldValue.$nin !== 'undefined') {
      throw new _node.default.Error(_node.default.Error.INVALID_JSON, 'bad $nin value');
    }

    if (Array.isArray(fieldValue.$all) && isArrayField) {
      if (isAnyValueRegexStartsWith(fieldValue.$all)) {
        if (!isAllValuesRegexOrNone(fieldValue.$all)) {
          throw new _node.default.Error(_node.default.Error.INVALID_JSON, 'All $all values must be of regex type or none: ' + fieldValue.$all);
        }

        for (let i = 0; i < fieldValue.$all.length; i += 1) {
          const value = processRegexPattern(fieldValue.$all[i].$regex);
          fieldValue.$all[i] = value.substring(1) + '%';
        }

        patterns.push(`array_contains_all_regex($${index}:name, $${index + 1}::jsonb)`);
      } else {
        patterns.push(`array_contains_all($${index}:name, $${index + 1}::jsonb)`);
      }

      values.push(fieldName, JSON.stringify(fieldValue.$all));
      index += 2;
    } else if (Array.isArray(fieldValue.$all)) {
      if (fieldValue.$all.length === 1) {
        patterns.push(`$${index}:name = $${index + 1}`);
        values.push(fieldName, fieldValue.$all[0].objectId);
        index += 2;
      }
    }

    if (typeof fieldValue.$exists !== 'undefined') {
      if (fieldValue.$exists) {
        patterns.push(`$${index}:name IS NOT NULL`);
      } else {
        patterns.push(`$${index}:name IS NULL`);
      }

      values.push(fieldName);
      index += 1;
    }

    if (fieldValue.$containedBy) {
      const arr = fieldValue.$containedBy;

      if (!(arr instanceof Array)) {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, `bad $containedBy: should be an array`);
      }

      patterns.push(`$${index}:name <@ $${index + 1}::jsonb`);
      values.push(fieldName, JSON.stringify(arr));
      index += 2;
    }

    if (fieldValue.$text) {
      const search = fieldValue.$text.$search;
      let language = 'english';

      if (typeof search !== 'object') {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, `bad $text: $search, should be object`);
      }

      if (!search.$term || typeof search.$term !== 'string') {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, `bad $text: $term, should be string`);
      }

      if (search.$language && typeof search.$language !== 'string') {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, `bad $text: $language, should be string`);
      } else if (search.$language) {
        language = search.$language;
      }

      if (search.$caseSensitive && typeof search.$caseSensitive !== 'boolean') {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, `bad $text: $caseSensitive, should be boolean`);
      } else if (search.$caseSensitive) {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, `bad $text: $caseSensitive not supported, please use $regex or create a separate lower case column.`);
      }

      if (search.$diacriticSensitive && typeof search.$diacriticSensitive !== 'boolean') {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, `bad $text: $diacriticSensitive, should be boolean`);
      } else if (search.$diacriticSensitive === false) {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, `bad $text: $diacriticSensitive - false not supported, install Postgres Unaccent Extension`);
      }

      patterns.push(`to_tsvector($${index}, $${index + 1}:name) @@ to_tsquery($${index + 2}, $${index + 3})`);
      values.push(language, fieldName, language, search.$term);
      index += 4;
    }

    if (fieldValue.$nearSphere) {
      const point = fieldValue.$nearSphere;
      const distance = fieldValue.$maxDistance;
      const distanceInKM = distance * 6371 * 1000;
      patterns.push(`ST_DistanceSphere($${index}:name::geometry, POINT($${index + 1}, $${index + 2})::geometry) <= $${index + 3}`);
      sorts.push(`ST_DistanceSphere($${index}:name::geometry, POINT($${index + 1}, $${index + 2})::geometry) ASC`);
      values.push(fieldName, point.longitude, point.latitude, distanceInKM);
      index += 4;
    }

    if (fieldValue.$within && fieldValue.$within.$box) {
      const box = fieldValue.$within.$box;
      const left = box[0].longitude;
      const bottom = box[0].latitude;
      const right = box[1].longitude;
      const top = box[1].latitude;
      patterns.push(`$${index}:name::point <@ $${index + 1}::box`);
      values.push(fieldName, `((${left}, ${bottom}), (${right}, ${top}))`);
      index += 2;
    }

    if (fieldValue.$geoWithin && fieldValue.$geoWithin.$centerSphere) {
      const centerSphere = fieldValue.$geoWithin.$centerSphere;

      if (!(centerSphere instanceof Array) || centerSphere.length < 2) {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, 'bad $geoWithin value; $centerSphere should be an array of Parse.GeoPoint and distance');
      } // Get point, convert to geo point if necessary and validate


      let point = centerSphere[0];

      if (point instanceof Array && point.length === 2) {
        point = new _node.default.GeoPoint(point[1], point[0]);
      } else if (!GeoPointCoder.isValidJSON(point)) {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, 'bad $geoWithin value; $centerSphere geo point invalid');
      }

      _node.default.GeoPoint._validate(point.latitude, point.longitude); // Get distance and validate


      const distance = centerSphere[1];

      if (isNaN(distance) || distance < 0) {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, 'bad $geoWithin value; $centerSphere distance invalid');
      }

      const distanceInKM = distance * 6371 * 1000;
      patterns.push(`ST_DistanceSphere($${index}:name::geometry, POINT($${index + 1}, $${index + 2})::geometry) <= $${index + 3}`);
      values.push(fieldName, point.longitude, point.latitude, distanceInKM);
      index += 4;
    }

    if (fieldValue.$geoWithin && fieldValue.$geoWithin.$polygon) {
      const polygon = fieldValue.$geoWithin.$polygon;
      let points;

      if (typeof polygon === 'object' && polygon.__type === 'Polygon') {
        if (!polygon.coordinates || polygon.coordinates.length < 3) {
          throw new _node.default.Error(_node.default.Error.INVALID_JSON, 'bad $geoWithin value; Polygon.coordinates should contain at least 3 lon/lat pairs');
        }

        points = polygon.coordinates;
      } else if (polygon instanceof Array) {
        if (polygon.length < 3) {
          throw new _node.default.Error(_node.default.Error.INVALID_JSON, 'bad $geoWithin value; $polygon should contain at least 3 GeoPoints');
        }

        points = polygon;
      } else {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, "bad $geoWithin value; $polygon should be Polygon object or Array of Parse.GeoPoint's");
      }

      points = points.map(point => {
        if (point instanceof Array && point.length === 2) {
          _node.default.GeoPoint._validate(point[1], point[0]);

          return `(${point[0]}, ${point[1]})`;
        }

        if (typeof point !== 'object' || point.__type !== 'GeoPoint') {
          throw new _node.default.Error(_node.default.Error.INVALID_JSON, 'bad $geoWithin value');
        } else {
          _node.default.GeoPoint._validate(point.latitude, point.longitude);
        }

        return `(${point.longitude}, ${point.latitude})`;
      }).join(', ');
      patterns.push(`$${index}:name::point <@ $${index + 1}::polygon`);
      values.push(fieldName, `(${points})`);
      index += 2;
    }

    if (fieldValue.$geoIntersects && fieldValue.$geoIntersects.$point) {
      const point = fieldValue.$geoIntersects.$point;

      if (typeof point !== 'object' || point.__type !== 'GeoPoint') {
        throw new _node.default.Error(_node.default.Error.INVALID_JSON, 'bad $geoIntersect value; $point should be GeoPoint');
      } else {
        _node.default.GeoPoint._validate(point.latitude, point.longitude);
      }

      patterns.push(`$${index}:name::polygon @> $${index + 1}::point`);
      values.push(fieldName, `(${point.longitude}, ${point.latitude})`);
      index += 2;
    }

    if (fieldValue.$regex) {
      let regex = fieldValue.$regex;
      let operator = '~';
      const opts = fieldValue.$options;

      if (opts) {
        if (opts.indexOf('i') >= 0) {
          operator = '~*';
        }

        if (opts.indexOf('x') >= 0) {
          regex = removeWhiteSpace(regex);
        }
      }

      const name = transformDotField(fieldName);
      regex = processRegexPattern(regex);
      patterns.push(`$${index}:raw ${operator} '$${index + 1}:raw'`);
      values.push(name, regex);
      index += 2;
    }

    if (fieldValue.__type === 'Pointer') {
      if (isArrayField) {
        patterns.push(`array_contains($${index}:name, $${index + 1})`);
        values.push(fieldName, JSON.stringify([fieldValue]));
        index += 2;
      } else {
        patterns.push(`$${index}:name = $${index + 1}`);
        values.push(fieldName, fieldValue.objectId);
        index += 2;
      }
    }

    if (fieldValue.__type === 'Date') {
      patterns.push(`$${index}:name = $${index + 1}`);
      values.push(fieldName, fieldValue.iso);
      index += 2;
    }

    if (fieldValue.__type === 'GeoPoint') {
      patterns.push(`$${index}:name ~= POINT($${index + 1}, $${index + 2})`);
      values.push(fieldName, fieldValue.longitude, fieldValue.latitude);
      index += 3;
    }

    if (fieldValue.__type === 'Polygon') {
      const value = convertPolygonToSQL(fieldValue.coordinates);
      patterns.push(`$${index}:name ~= $${index + 1}::polygon`);
      values.push(fieldName, value);
      index += 2;
    }

    Object.keys(ParseToPosgresComparator).forEach(cmp => {
      if (fieldValue[cmp] || fieldValue[cmp] === 0) {
        const pgComparator = ParseToPosgresComparator[cmp];
        const postgresValue = toPostgresValue(fieldValue[cmp]);
        let constraintFieldName;

        if (fieldName.indexOf('.') >= 0) {
          let castType;

          switch (typeof postgresValue) {
            case 'number':
              castType = 'double precision';
              break;

            case 'boolean':
              castType = 'boolean';
              break;

            default:
              castType = undefined;
          }

          constraintFieldName = castType ? `CAST ((${transformDotField(fieldName)}) AS ${castType})` : transformDotField(fieldName);
        } else {
          constraintFieldName = `$${index++}:name`;
          values.push(fieldName);
        }

        values.push(postgresValue);
        patterns.push(`${constraintFieldName} ${pgComparator} $${index++}`);
      }
    });

    if (initialPatternsLength === patterns.length) {
      throw new _node.default.Error(_node.default.Error.OPERATION_FORBIDDEN, `Postgres doesn't support this query type yet ${JSON.stringify(fieldValue)}`);
    }
  }

  values = values.map(transformValue);
  return {
    pattern: patterns.join(' AND '),
    values,
    sorts
  };
};

class PostgresStorageAdapter {
  // Private
  constructor({
    uri,
    collectionPrefix = '',
    databaseOptions = {}
  }) {
    this._collectionPrefix = collectionPrefix;
    this.enableSchemaHooks = !!databaseOptions.enableSchemaHooks;
    delete databaseOptions.enableSchemaHooks;
    const {
      client,
      pgp
    } = (0, _PostgresClient.createClient)(uri, databaseOptions);
    this._client = client;

    this._onchange = () => {};

    this._pgp = pgp;
    this._uuid = (0, _uuid.v4)();
    this.canSortOnJoinTables = false;
  }

  watch(callback) {
    this._onchange = callback;
  } //Note that analyze=true will run the query, executing INSERTS, DELETES, etc.


  createExplainableQuery(query, analyze = false) {
    if (analyze) {
      return 'EXPLAIN (ANALYZE, FORMAT JSON) ' + query;
    } else {
      return 'EXPLAIN (FORMAT JSON) ' + query;
    }
  }

  handleShutdown() {
    if (this._stream) {
      this._stream.done();

      delete this._stream;
    }

    if (!this._client) {
      return;
    }

    this._client.$pool.end();
  }

  async _listenToSchema() {
    if (!this._stream && this.enableSchemaHooks) {
      this._stream = await this._client.connect({
        direct: true
      });

      this._stream.client.on('notification', data => {
        const payload = JSON.parse(data.payload);

        if (payload.senderId !== this._uuid) {
          this._onchange();
        }
      });

      await this._stream.none('LISTEN $1~', 'schema.change');
    }
  }

  _notifySchemaChange() {
    if (this._stream) {
      this._stream.none('NOTIFY $1~, $2', ['schema.change', {
        senderId: this._uuid
      }]).catch(error => {
        console.log('Failed to Notify:', error); // unlikely to ever happen
      });
    }
  }

  async _ensureSchemaCollectionExists(conn) {
    conn = conn || this._client;
    await conn.none('CREATE TABLE IF NOT EXISTS "_SCHEMA" ( "className" varChar(120), "schema" jsonb, "isParseClass" bool, PRIMARY KEY ("className") )').catch(error => {
      if (error.code === PostgresDuplicateRelationError || error.code === PostgresUniqueIndexViolationError || error.code === PostgresDuplicateObjectError) {// Table already exists, must have been created by a different request. Ignore error.
      } else {
        throw error;
      }
    });
  }

  async classExists(name) {
    return this._client.one('SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)', [name], a => a.exists);
  }

  async setClassLevelPermissions(className, CLPs) {
    await this._client.task('set-class-level-permissions', async t => {
      const values = [className, 'schema', 'classLevelPermissions', JSON.stringify(CLPs)];
      await t.none(`UPDATE "_SCHEMA" SET $2:name = json_object_set_key($2:name, $3::text, $4::jsonb) WHERE "className" = $1`, values);
    });

    this._notifySchemaChange();
  }

  async setIndexesWithSchemaFormat(className, submittedIndexes, existingIndexes = {}, fields, conn) {
    conn = conn || this._client;
    const self = this;

    if (submittedIndexes === undefined) {
      return Promise.resolve();
    }

    if (Object.keys(existingIndexes).length === 0) {
      existingIndexes = {
        _id_: {
          _id: 1
        }
      };
    }

    const deletedIndexes = [];
    const insertedIndexes = [];
    Object.keys(submittedIndexes).forEach(name => {
      const field = submittedIndexes[name];

      if (existingIndexes[name] && field.__op !== 'Delete') {
        throw new _node.default.Error(_node.default.Error.INVALID_QUERY, `Index ${name} exists, cannot update.`);
      }

      if (!existingIndexes[name] && field.__op === 'Delete') {
        throw new _node.default.Error(_node.default.Error.INVALID_QUERY, `Index ${name} does not exist, cannot delete.`);
      }

      if (field.__op === 'Delete') {
        deletedIndexes.push(name);
        delete existingIndexes[name];
      } else {
        Object.keys(field).forEach(key => {
          if (!Object.prototype.hasOwnProperty.call(fields, key)) {
            throw new _node.default.Error(_node.default.Error.INVALID_QUERY, `Field ${key} does not exist, cannot add index.`);
          }
        });
        existingIndexes[name] = field;
        insertedIndexes.push({
          key: field,
          name
        });
      }
    });
    await conn.tx('set-indexes-with-schema-format', async t => {
      if (insertedIndexes.length > 0) {
        await self.createIndexes(className, insertedIndexes, t);
      }

      if (deletedIndexes.length > 0) {
        await self.dropIndexes(className, deletedIndexes, t);
      }

      await t.none('UPDATE "_SCHEMA" SET $2:name = json_object_set_key($2:name, $3::text, $4::jsonb) WHERE "className" = $1', [className, 'schema', 'indexes', JSON.stringify(existingIndexes)]);
    });

    this._notifySchemaChange();
  }

  async createClass(className, schema, conn) {
    conn = conn || this._client;
    const parseSchema = await conn.tx('create-class', async t => {
      await this.createTable(className, schema, t);
      await t.none('INSERT INTO "_SCHEMA" ("className", "schema", "isParseClass") VALUES ($<className>, $<schema>, true)', {
        className,
        schema
      });
      await this.setIndexesWithSchemaFormat(className, schema.indexes, {}, schema.fields, t);
      return toParseSchema(schema);
    }).catch(err => {
      if (err.code === PostgresUniqueIndexViolationError && err.detail.includes(className)) {
        throw new _node.default.Error(_node.default.Error.DUPLICATE_VALUE, `Class ${className} already exists.`);
      }

      throw err;
    });

    this._notifySchemaChange();

    return parseSchema;
  } // Just create a table, do not insert in schema


  async createTable(className, schema, conn) {
    conn = conn || this._client;
    debug('createTable');
    const valuesArray = [];
    const patternsArray = [];
    const fields = Object.assign({}, schema.fields);

    if (className === '_User') {
      fields._email_verify_token_expires_at = {
        type: 'Date'
      };
      fields._email_verify_token = {
        type: 'String'
      };
      fields._account_lockout_expires_at = {
        type: 'Date'
      };
      fields._failed_login_count = {
        type: 'Number'
      };
      fields._perishable_token = {
        type: 'String'
      };
      fields._perishable_token_expires_at = {
        type: 'Date'
      };
      fields._password_changed_at = {
        type: 'Date'
      };
      fields._password_history = {
        type: 'Array'
      };
    }

    let index = 2;
    const relations = [];
    Object.keys(fields).forEach(fieldName => {
      const parseType = fields[fieldName]; // Skip when it's a relation
      // We'll create the tables later

      if (parseType.type === 'Relation') {
        relations.push(fieldName);
        return;
      }

      if (['_rperm', '_wperm'].indexOf(fieldName) >= 0) {
        parseType.contents = {
          type: 'String'
        };
      }

      valuesArray.push(fieldName);
      valuesArray.push(parseTypeToPostgresType(parseType));
      patternsArray.push(`$${index}:name $${index + 1}:raw`);

      if (fieldName === 'objectId') {
        patternsArray.push(`PRIMARY KEY ($${index}:name)`);
      }

      index = index + 2;
    });
    const qs = `CREATE TABLE IF NOT EXISTS $1:name (${patternsArray.join()})`;
    const values = [className, ...valuesArray];
    return conn.task('create-table', async t => {
      try {
        await t.none(qs, values);
      } catch (error) {
        if (error.code !== PostgresDuplicateRelationError) {
          throw error;
        } // ELSE: Table already exists, must have been created by a different request. Ignore the error.

      }

      await t.tx('create-table-tx', tx => {
        return tx.batch(relations.map(fieldName => {
          return tx.none('CREATE TABLE IF NOT EXISTS $<joinTable:name> ("relatedId" varChar(120), "owningId" varChar(120), PRIMARY KEY("relatedId", "owningId") )', {
            joinTable: `_Join:${fieldName}:${className}`
          });
        }));
      });
    });
  }

  async schemaUpgrade(className, schema, conn) {
    debug('schemaUpgrade');
    conn = conn || this._client;
    const self = this;
    await conn.tx('schema-upgrade', async t => {
      const columns = await t.map('SELECT column_name FROM information_schema.columns WHERE table_name = $<className>', {
        className
      }, a => a.column_name);
      const newColumns = Object.keys(schema.fields).filter(item => columns.indexOf(item) === -1).map(fieldName => self.addFieldIfNotExists(className, fieldName, schema.fields[fieldName], t));
      await t.batch(newColumns);
    });
  }

  async addFieldIfNotExists(className, fieldName, type, conn) {
    // TODO: Must be revised for invalid logic...
    debug('addFieldIfNotExists');
    conn = conn || this._client;
    const self = this;
    await conn.tx('add-field-if-not-exists', async t => {
      if (type.type !== 'Relation') {
        try {
          await t.none('ALTER TABLE $<className:name> ADD COLUMN IF NOT EXISTS $<fieldName:name> $<postgresType:raw>', {
            className,
            fieldName,
            postgresType: parseTypeToPostgresType(type)
          });
        } catch (error) {
          if (error.code === PostgresRelationDoesNotExistError) {
            return self.createClass(className, {
              fields: {
                [fieldName]: type
              }
            }, t);
          }

          if (error.code !== PostgresDuplicateColumnError) {
            throw error;
          } // Column already exists, created by other request. Carry on to see if it's the right type.

        }
      } else {
        await t.none('CREATE TABLE IF NOT EXISTS $<joinTable:name> ("relatedId" varChar(120), "owningId" varChar(120), PRIMARY KEY("relatedId", "owningId") )', {
          joinTable: `_Join:${fieldName}:${className}`
        });
      }

      const result = await t.any('SELECT "schema" FROM "_SCHEMA" WHERE "className" = $<className> and ("schema"::json->\'fields\'->$<fieldName>) is not null', {
        className,
        fieldName
      });

      if (result[0]) {
        throw 'Attempted to add a field that already exists';
      } else {
        const path = `{fields,${fieldName}}`;
        await t.none('UPDATE "_SCHEMA" SET "schema"=jsonb_set("schema", $<path>, $<type>)  WHERE "className"=$<className>', {
          path,
          type,
          className
        });
      }
    });

    this._notifySchemaChange();
  } // Drops a collection. Resolves with true if it was a Parse Schema (eg. _User, Custom, etc.)
  // and resolves with false if it wasn't (eg. a join table). Rejects if deletion was impossible.


  async deleteClass(className) {
    const operations = [{
      query: `DROP TABLE IF EXISTS $1:name`,
      values: [className]
    }, {
      query: `DELETE FROM "_SCHEMA" WHERE "className" = $1`,
      values: [className]
    }];
    const response = await this._client.tx(t => t.none(this._pgp.helpers.concat(operations))).then(() => className.indexOf('_Join:') != 0); // resolves with false when _Join table

    this._notifySchemaChange();

    return response;
  } // Delete all data known to this adapter. Used for testing.


  async deleteAllClasses() {
    const now = new Date().getTime();
    const helpers = this._pgp.helpers;
    debug('deleteAllClasses');
    await this._client.task('delete-all-classes', async t => {
      try {
        const results = await t.any('SELECT * FROM "_SCHEMA"');
        const joins = results.reduce((list, schema) => {
          return list.concat(joinTablesForSchema(schema.schema));
        }, []);
        const classes = ['_SCHEMA', '_PushStatus', '_JobStatus', '_JobSchedule', '_Hooks', '_GlobalConfig', '_GraphQLConfig', '_Audience', '_Idempotency', ...results.map(result => result.className), ...joins];
        const queries = classes.map(className => ({
          query: 'DROP TABLE IF EXISTS $<className:name>',
          values: {
            className
          }
        }));
        await t.tx(tx => tx.none(helpers.concat(queries)));
      } catch (error) {
        if (error.code !== PostgresRelationDoesNotExistError) {
          throw error;
        } // No _SCHEMA collection. Don't delete anything.

      }
    }).then(() => {
      debug(`deleteAllClasses done in ${new Date().getTime() - now}`);
    });
  } // Remove the column and all the data. For Relations, the _Join collection is handled
  // specially, this function does not delete _Join columns. It should, however, indicate
  // that the relation fields does not exist anymore. In mongo, this means removing it from
  // the _SCHEMA collection.  There should be no actual data in the collection under the same name
  // as the relation column, so it's fine to attempt to delete it. If the fields listed to be
  // deleted do not exist, this function should return successfully anyways. Checking for
  // attempts to delete non-existent fields is the responsibility of Parse Server.
  // This function is not obligated to delete fields atomically. It is given the field
  // names in a list so that databases that are capable of deleting fields atomically
  // may do so.
  // Returns a Promise.


  async deleteFields(className, schema, fieldNames) {
    debug('deleteFields');
    fieldNames = fieldNames.reduce((list, fieldName) => {
      const field = schema.fields[fieldName];

      if (field.type !== 'Relation') {
        list.push(fieldName);
      }

      delete schema.fields[fieldName];
      return list;
    }, []);
    const values = [className, ...fieldNames];
    const columns = fieldNames.map((name, idx) => {
      return `$${idx + 2}:name`;
    }).join(', DROP COLUMN');
    await this._client.tx('delete-fields', async t => {
      await t.none('UPDATE "_SCHEMA" SET "schema" = $<schema> WHERE "className" = $<className>', {
        schema,
        className
      });

      if (values.length > 1) {
        await t.none(`ALTER TABLE $1:name DROP COLUMN IF EXISTS ${columns}`, values);
      }
    });

    this._notifySchemaChange();
  } // Return a promise for all schemas known to this adapter, in Parse format. In case the
  // schemas cannot be retrieved, returns a promise that rejects. Requirements for the
  // rejection reason are TBD.


  async getAllClasses() {
    return this._client.task('get-all-classes', async t => {
      return await t.map('SELECT * FROM "_SCHEMA"', null, row => toParseSchema(_objectSpread({
        className: row.className
      }, row.schema)));
    });
  } // Return a promise for the schema with the given name, in Parse format. If
  // this adapter doesn't know about the schema, return a promise that rejects with
  // undefined as the reason.


  async getClass(className) {
    debug('getClass');
    return this._client.any('SELECT * FROM "_SCHEMA" WHERE "className" = $<className>', {
      className
    }).then(result => {
      if (result.length !== 1) {
        throw undefined;
      }

      return result[0].schema;
    }).then(toParseSchema);
  } // TODO: remove the mongo format dependency in the return value


  async createObject(className, schema, object, transactionalSession) {
    debug('createObject');
    let columnsArray = [];
    const valuesArray = [];
    schema = toPostgresSchema(schema);
    const geoPoints = {};
    object = handleDotFields(object);
    validateKeys(object);
    Object.keys(object).forEach(fieldName => {
      if (object[fieldName] === null) {
        return;
      }

      var authDataMatch = fieldName.match(/^_auth_data_([a-zA-Z0-9_]+)$/);

      if (authDataMatch) {
        var provider = authDataMatch[1];
        object['authData'] = object['authData'] || {};
        object['authData'][provider] = object[fieldName];
        delete object[fieldName];
        fieldName = 'authData';
      }

      columnsArray.push(fieldName);

      if (!schema.fields[fieldName] && className === '_User') {
        if (fieldName === '_email_verify_token' || fieldName === '_failed_login_count' || fieldName === '_perishable_token' || fieldName === '_password_history') {
          valuesArray.push(object[fieldName]);
        }

        if (fieldName === '_email_verify_token_expires_at') {
          if (object[fieldName]) {
            valuesArray.push(object[fieldName].iso);
          } else {
            valuesArray.push(null);
          }
        }

        if (fieldName === '_account_lockout_expires_at' || fieldName === '_perishable_token_expires_at' || fieldName === '_password_changed_at') {
          if (object[fieldName]) {
            valuesArray.push(object[fieldName].iso);
          } else {
            valuesArray.push(null);
          }
        }

        return;
      }

      switch (schema.fields[fieldName].type) {
        case 'Date':
          if (object[fieldName]) {
            valuesArray.push(object[fieldName].iso);
          } else {
            valuesArray.push(null);
          }

          break;

        case 'Pointer':
          valuesArray.push(object[fieldName].objectId);
          break;

        case 'Array':
          if (['_rperm', '_wperm'].indexOf(fieldName) >= 0) {
            valuesArray.push(object[fieldName]);
          } else {
            valuesArray.push(JSON.stringify(object[fieldName]));
          }

          break;

        case 'Object':
        case 'Bytes':
        case 'String':
        case 'Number':
        case 'Boolean':
          valuesArray.push(object[fieldName]);
          break;

        case 'File':
          valuesArray.push(object[fieldName].name);
          break;

        case 'Polygon':
          {
            const value = convertPolygonToSQL(object[fieldName].coordinates);
            valuesArray.push(value);
            break;
          }

        case 'GeoPoint':
          // pop the point and process later
          geoPoints[fieldName] = object[fieldName];
          columnsArray.pop();
          break;

        default:
          throw `Type ${schema.fields[fieldName].type} not supported yet`;
      }
    });
    columnsArray = columnsArray.concat(Object.keys(geoPoints));
    const initialValues = valuesArray.map((val, index) => {
      let termination = '';
      const fieldName = columnsArray[index];

      if (['_rperm', '_wperm'].indexOf(fieldName) >= 0) {
        termination = '::text[]';
      } else if (schema.fields[fieldName] && schema.fields[fieldName].type === 'Array') {
        termination = '::jsonb';
      }

      return `$${index + 2 + columnsArray.length}${termination}`;
    });
    const geoPointsInjects = Object.keys(geoPoints).map(key => {
      const value = geoPoints[key];
      valuesArray.push(value.longitude, value.latitude);
      const l = valuesArray.length + columnsArray.length;
      return `POINT($${l}, $${l + 1})`;
    });
    const columnsPattern = columnsArray.map((col, index) => `$${index + 2}:name`).join();
    const valuesPattern = initialValues.concat(geoPointsInjects).join();
    const qs = `INSERT INTO $1:name (${columnsPattern}) VALUES (${valuesPattern})`;
    const values = [className, ...columnsArray, ...valuesArray];
    const promise = (transactionalSession ? transactionalSession.t : this._client).none(qs, values).then(() => ({
      ops: [object]
    })).catch(error => {
      if (error.code === PostgresUniqueIndexViolationError) {
        const err = new _node.default.Error(_node.default.Error.DUPLICATE_VALUE, 'A duplicate value for a field with unique values was provided');
        err.underlyingError = error;

        if (error.constraint) {
          const matches = error.constraint.match(/unique_([a-zA-Z]+)/);

          if (matches && Array.isArray(matches)) {
            err.userInfo = {
              duplicated_field: matches[1]
            };
          }
        }

        error = err;
      }

      throw error;
    });

    if (transactionalSession) {
      transactionalSession.batch.push(promise);
    }

    return promise;
  } // Remove all objects that match the given Parse Query.
  // If no objects match, reject with OBJECT_NOT_FOUND. If objects are found and deleted, resolve with undefined.
  // If there is some other error, reject with INTERNAL_SERVER_ERROR.


  async deleteObjectsByQuery(className, schema, query, transactionalSession) {
    debug('deleteObjectsByQuery');
    const values = [className];
    const index = 2;
    const where = buildWhereClause({
      schema,
      index,
      query,
      caseInsensitive: false
    });
    values.push(...where.values);

    if (Object.keys(query).length === 0) {
      where.pattern = 'TRUE';
    }

    const qs = `WITH deleted AS (DELETE FROM $1:name WHERE ${where.pattern} RETURNING *) SELECT count(*) FROM deleted`;
    const promise = (transactionalSession ? transactionalSession.t : this._client).one(qs, values, a => +a.count).then(count => {
      if (count === 0) {
        throw new _node.default.Error(_node.default.Error.OBJECT_NOT_FOUND, 'Object not found.');
      } else {
        return count;
      }
    }).catch(error => {
      if (error.code !== PostgresRelationDoesNotExistError) {
        throw error;
      } // ELSE: Don't delete anything if doesn't exist

    });

    if (transactionalSession) {
      transactionalSession.batch.push(promise);
    }

    return promise;
  } // Return value not currently well specified.


  async findOneAndUpdate(className, schema, query, update, transactionalSession) {
    debug('findOneAndUpdate');
    return this.updateObjectsByQuery(className, schema, query, update, transactionalSession).then(val => val[0]);
  } // Apply the update to all objects that match the given Parse Query.


  async updateObjectsByQuery(className, schema, query, update, transactionalSession) {
    debug('updateObjectsByQuery');
    const updatePatterns = [];
    const values = [className];
    let index = 2;
    schema = toPostgresSchema(schema);

    const originalUpdate = _objectSpread({}, update); // Set flag for dot notation fields


    const dotNotationOptions = {};
    Object.keys(update).forEach(fieldName => {
      if (fieldName.indexOf('.') > -1) {
        const components = fieldName.split('.');
        const first = components.shift();
        dotNotationOptions[first] = true;
      } else {
        dotNotationOptions[fieldName] = false;
      }
    });
    update = handleDotFields(update); // Resolve authData first,
    // So we don't end up with multiple key updates

    for (const fieldName in update) {
      const authDataMatch = fieldName.match(/^_auth_data_([a-zA-Z0-9_]+)$/);

      if (authDataMatch) {
        var provider = authDataMatch[1];
        const value = update[fieldName];
        delete update[fieldName];
        update['authData'] = update['authData'] || {};
        update['authData'][provider] = value;
      }
    }

    for (const fieldName in update) {
      const fieldValue = update[fieldName]; // Drop any undefined values.

      if (typeof fieldValue === 'undefined') {
        delete update[fieldName];
      } else if (fieldValue === null) {
        updatePatterns.push(`$${index}:name = NULL`);
        values.push(fieldName);
        index += 1;
      } else if (fieldName == 'authData') {
        // This recursively sets the json_object
        // Only 1 level deep
        const generate = (jsonb, key, value) => {
          return `json_object_set_key(COALESCE(${jsonb}, '{}'::jsonb), ${key}, ${value})::jsonb`;
        };

        const lastKey = `$${index}:name`;
        const fieldNameIndex = index;
        index += 1;
        values.push(fieldName);
        const update = Object.keys(fieldValue).reduce((lastKey, key) => {
          const str = generate(lastKey, `$${index}::text`, `$${index + 1}::jsonb`);
          index += 2;
          let value = fieldValue[key];

          if (value) {
            if (value.__op === 'Delete') {
              value = null;
            } else {
              value = JSON.stringify(value);
            }
          }

          values.push(key, value);
          return str;
        }, lastKey);
        updatePatterns.push(`$${fieldNameIndex}:name = ${update}`);
      } else if (fieldValue.__op === 'Increment') {
        updatePatterns.push(`$${index}:name = COALESCE($${index}:name, 0) + $${index + 1}`);
        values.push(fieldName, fieldValue.amount);
        index += 2;
      } else if (fieldValue.__op === 'Add') {
        updatePatterns.push(`$${index}:name = array_add(COALESCE($${index}:name, '[]'::jsonb), $${index + 1}::jsonb)`);
        values.push(fieldName, JSON.stringify(fieldValue.objects));
        index += 2;
      } else if (fieldValue.__op === 'Delete') {
        updatePatterns.push(`$${index}:name = $${index + 1}`);
        values.push(fieldName, null);
        index += 2;
      } else if (fieldValue.__op === 'Remove') {
        updatePatterns.push(`$${index}:name = array_remove(COALESCE($${index}:name, '[]'::jsonb), $${index + 1}::jsonb)`);
        values.push(fieldName, JSON.stringify(fieldValue.objects));
        index += 2;
      } else if (fieldValue.__op === 'AddUnique') {
        updatePatterns.push(`$${index}:name = array_add_unique(COALESCE($${index}:name, '[]'::jsonb), $${index + 1}::jsonb)`);
        values.push(fieldName, JSON.stringify(fieldValue.objects));
        index += 2;
      } else if (fieldName === 'updatedAt') {
        //TODO: stop special casing this. It should check for __type === 'Date' and use .iso
        updatePatterns.push(`$${index}:name = $${index + 1}`);
        values.push(fieldName, fieldValue);
        index += 2;
      } else if (typeof fieldValue === 'string') {
        updatePatterns.push(`$${index}:name = $${index + 1}`);
        values.push(fieldName, fieldValue);
        index += 2;
      } else if (typeof fieldValue === 'boolean') {
        updatePatterns.push(`$${index}:name = $${index + 1}`);
        values.push(fieldName, fieldValue);
        index += 2;
      } else if (fieldValue.__type === 'Pointer') {
        updatePatterns.push(`$${index}:name = $${index + 1}`);
        values.push(fieldName, fieldValue.objectId);
        index += 2;
      } else if (fieldValue.__type === 'Date') {
        updatePatterns.push(`$${index}:name = $${index + 1}`);
        values.push(fieldName, toPostgresValue(fieldValue));
        index += 2;
      } else if (fieldValue instanceof Date) {
        updatePatterns.push(`$${index}:name = $${index + 1}`);
        values.push(fieldName, fieldValue);
        index += 2;
      } else if (fieldValue.__type === 'File') {
        updatePatterns.push(`$${index}:name = $${index + 1}`);
        values.push(fieldName, toPostgresValue(fieldValue));
        index += 2;
      } else if (fieldValue.__type === 'GeoPoint') {
        updatePatterns.push(`$${index}:name = POINT($${index + 1}, $${index + 2})`);
        values.push(fieldName, fieldValue.longitude, fieldValue.latitude);
        index += 3;
      } else if (fieldValue.__type === 'Polygon') {
        const value = convertPolygonToSQL(fieldValue.coordinates);
        updatePatterns.push(`$${index}:name = $${index + 1}::polygon`);
        values.push(fieldName, value);
        index += 2;
      } else if (fieldValue.__type === 'Relation') {// noop
      } else if (typeof fieldValue === 'number') {
        updatePatterns.push(`$${index}:name = $${index + 1}`);
        values.push(fieldName, fieldValue);
        index += 2;
      } else if (typeof fieldValue === 'object' && schema.fields[fieldName] && schema.fields[fieldName].type === 'Object') {
        // Gather keys to increment
        const keysToIncrement = Object.keys(originalUpdate).filter(k => {
          // choose top level fields that have a delete operation set
          // Note that Object.keys is iterating over the **original** update object
          // and that some of the keys of the original update could be null or undefined:
          // (See the above check `if (fieldValue === null || typeof fieldValue == "undefined")`)
          const value = originalUpdate[k];
          return value && value.__op === 'Increment' && k.split('.').length === 2 && k.split('.')[0] === fieldName;
        }).map(k => k.split('.')[1]);
        let incrementPatterns = '';

        if (keysToIncrement.length > 0) {
          incrementPatterns = ' || ' + keysToIncrement.map(c => {
            const amount = fieldValue[c].amount;
            return `CONCAT('{"${c}":', COALESCE($${index}:name->>'${c}','0')::int + ${amount}, '}')::jsonb`;
          }).join(' || '); // Strip the keys

          keysToIncrement.forEach(key => {
            delete fieldValue[key];
          });
        }

        const keysToDelete = Object.keys(originalUpdate).filter(k => {
          // choose top level fields that have a delete operation set.
          const value = originalUpdate[k];
          return value && value.__op === 'Delete' && k.split('.').length === 2 && k.split('.')[0] === fieldName;
        }).map(k => k.split('.')[1]);
        const deletePatterns = keysToDelete.reduce((p, c, i) => {
          return p + ` - '$${index + 1 + i}:value'`;
        }, ''); // Override Object

        let updateObject = "'{}'::jsonb";

        if (dotNotationOptions[fieldName]) {
          // Merge Object
          updateObject = `COALESCE($${index}:name, '{}'::jsonb)`;
        }

        updatePatterns.push(`$${index}:name = (${updateObject} ${deletePatterns} ${incrementPatterns} || $${index + 1 + keysToDelete.length}::jsonb )`);
        values.push(fieldName, ...keysToDelete, JSON.stringify(fieldValue));
        index += 2 + keysToDelete.length;
      } else if (Array.isArray(fieldValue) && schema.fields[fieldName] && schema.fields[fieldName].type === 'Array') {
        const expectedType = parseTypeToPostgresType(schema.fields[fieldName]);

        if (expectedType === 'text[]') {
          updatePatterns.push(`$${index}:name = $${index + 1}::text[]`);
          values.push(fieldName, fieldValue);
          index += 2;
        } else {
          updatePatterns.push(`$${index}:name = $${index + 1}::jsonb`);
          values.push(fieldName, JSON.stringify(fieldValue));
          index += 2;
        }
      } else {
        debug('Not supported update', {
          fieldName,
          fieldValue
        });
        return Promise.reject(new _node.default.Error(_node.default.Error.OPERATION_FORBIDDEN, `Postgres doesn't support update ${JSON.stringify(fieldValue)} yet`));
      }
    }

    const where = buildWhereClause({
      schema,
      index,
      query,
      caseInsensitive: false
    });
    values.push(...where.values);
    const whereClause = where.pattern.length > 0 ? `WHERE ${where.pattern}` : '';
    const qs = `UPDATE $1:name SET ${updatePatterns.join()} ${whereClause} RETURNING *`;
    const promise = (transactionalSession ? transactionalSession.t : this._client).any(qs, values);

    if (transactionalSession) {
      transactionalSession.batch.push(promise);
    }

    return promise;
  } // Hopefully, we can get rid of this. It's only used for config and hooks.


  upsertOneObject(className, schema, query, update, transactionalSession) {
    debug('upsertOneObject');
    const createValue = Object.assign({}, query, update);
    return this.createObject(className, schema, createValue, transactionalSession).catch(error => {
      // ignore duplicate value errors as it's upsert
      if (error.code !== _node.default.Error.DUPLICATE_VALUE) {
        throw error;
      }

      return this.findOneAndUpdate(className, schema, query, update, transactionalSession);
    });
  }

  find(className, schema, query, {
    skip,
    limit,
    sort,
    keys,
    caseInsensitive,
    explain
  }) {
    debug('find');
    const hasLimit = limit !== undefined;
    const hasSkip = skip !== undefined;
    let values = [className];
    const where = buildWhereClause({
      schema,
      query,
      index: 2,
      caseInsensitive
    });
    values.push(...where.values);
    const wherePattern = where.pattern.length > 0 ? `WHERE ${where.pattern}` : '';
    const limitPattern = hasLimit ? `LIMIT $${values.length + 1}` : '';

    if (hasLimit) {
      values.push(limit);
    }

    const skipPattern = hasSkip ? `OFFSET $${values.length + 1}` : '';

    if (hasSkip) {
      values.push(skip);
    }

    let sortPattern = '';

    if (sort) {
      const sortCopy = sort;
      const sorting = Object.keys(sort).map(key => {
        const transformKey = transformDotFieldToComponents(key).join('->'); // Using $idx pattern gives:  non-integer constant in ORDER BY

        if (sortCopy[key] === 1) {
          return `${transformKey} ASC`;
        }

        return `${transformKey} DESC`;
      }).join();
      sortPattern = sort !== undefined && Object.keys(sort).length > 0 ? `ORDER BY ${sorting}` : '';
    }

    if (where.sorts && Object.keys(where.sorts).length > 0) {
      sortPattern = `ORDER BY ${where.sorts.join()}`;
    }

    let columns = '*';

    if (keys) {
      // Exclude empty keys
      // Replace ACL by it's keys
      keys = keys.reduce((memo, key) => {
        if (key === 'ACL') {
          memo.push('_rperm');
          memo.push('_wperm');
        } else if (key.length > 0) {
          memo.push(key);
        }

        return memo;
      }, []);
      columns = keys.map((key, index) => {
        if (key === '$score') {
          return `ts_rank_cd(to_tsvector($${2}, $${3}:name), to_tsquery($${4}, $${5}), 32) as score`;
        }

        return `$${index + values.length + 1}:name`;
      }).join();
      values = values.concat(keys);
    }

    const originalQuery = `SELECT ${columns} FROM $1:name ${wherePattern} ${sortPattern} ${limitPattern} ${skipPattern}`;
    const qs = explain ? this.createExplainableQuery(originalQuery) : originalQuery;
    return this._client.any(qs, values).catch(error => {
      // Query on non existing table, don't crash
      if (error.code !== PostgresRelationDoesNotExistError) {
        throw error;
      }

      return [];
    }).then(results => {
      if (explain) {
        return results;
      }

      return results.map(object => this.postgresObjectToParseObject(className, object, schema));
    });
  } // Converts from a postgres-format object to a REST-format object.
  // Does not strip out anything based on a lack of authentication.


  postgresObjectToParseObject(className, object, schema) {
    Object.keys(schema.fields).forEach(fieldName => {
      if (schema.fields[fieldName].type === 'Pointer' && object[fieldName]) {
        object[fieldName] = {
          objectId: object[fieldName],
          __type: 'Pointer',
          className: schema.fields[fieldName].targetClass
        };
      }

      if (schema.fields[fieldName].type === 'Relation') {
        object[fieldName] = {
          __type: 'Relation',
          className: schema.fields[fieldName].targetClass
        };
      }

      if (object[fieldName] && schema.fields[fieldName].type === 'GeoPoint') {
        object[fieldName] = {
          __type: 'GeoPoint',
          latitude: object[fieldName].y,
          longitude: object[fieldName].x
        };
      }

      if (object[fieldName] && schema.fields[fieldName].type === 'Polygon') {
        let coords = object[fieldName];
        coords = coords.substr(2, coords.length - 4).split('),(');
        coords = coords.map(point => {
          return [parseFloat(point.split(',')[1]), parseFloat(point.split(',')[0])];
        });
        object[fieldName] = {
          __type: 'Polygon',
          coordinates: coords
        };
      }

      if (object[fieldName] && schema.fields[fieldName].type === 'File') {
        object[fieldName] = {
          __type: 'File',
          name: object[fieldName]
        };
      }
    }); //TODO: remove this reliance on the mongo format. DB adapter shouldn't know there is a difference between created at and any other date field.

    if (object.createdAt) {
      object.createdAt = object.createdAt.toISOString();
    }

    if (object.updatedAt) {
      object.updatedAt = object.updatedAt.toISOString();
    }

    if (object.expiresAt) {
      object.expiresAt = {
        __type: 'Date',
        iso: object.expiresAt.toISOString()
      };
    }

    if (object._email_verify_token_expires_at) {
      object._email_verify_token_expires_at = {
        __type: 'Date',
        iso: object._email_verify_token_expires_at.toISOString()
      };
    }

    if (object._account_lockout_expires_at) {
      object._account_lockout_expires_at = {
        __type: 'Date',
        iso: object._account_lockout_expires_at.toISOString()
      };
    }

    if (object._perishable_token_expires_at) {
      object._perishable_token_expires_at = {
        __type: 'Date',
        iso: object._perishable_token_expires_at.toISOString()
      };
    }

    if (object._password_changed_at) {
      object._password_changed_at = {
        __type: 'Date',
        iso: object._password_changed_at.toISOString()
      };
    }

    for (const fieldName in object) {
      if (object[fieldName] === null) {
        delete object[fieldName];
      }

      if (object[fieldName] instanceof Date) {
        object[fieldName] = {
          __type: 'Date',
          iso: object[fieldName].toISOString()
        };
      }
    }

    return object;
  } // Create a unique index. Unique indexes on nullable fields are not allowed. Since we don't
  // currently know which fields are nullable and which aren't, we ignore that criteria.
  // As such, we shouldn't expose this function to users of parse until we have an out-of-band
  // Way of determining if a field is nullable. Undefined doesn't count against uniqueness,
  // which is why we use sparse indexes.


  async ensureUniqueness(className, schema, fieldNames) {
    const constraintName = `${className}_unique_${fieldNames.sort().join('_')}`;
    const constraintPatterns = fieldNames.map((fieldName, index) => `$${index + 3}:name`);
    const qs = `CREATE UNIQUE INDEX IF NOT EXISTS $2:name ON $1:name(${constraintPatterns.join()})`;
    return this._client.none(qs, [className, constraintName, ...fieldNames]).catch(error => {
      if (error.code === PostgresDuplicateRelationError && error.message.includes(constraintName)) {// Index already exists. Ignore error.
      } else if (error.code === PostgresUniqueIndexViolationError && error.message.includes(constraintName)) {
        // Cast the error into the proper parse error
        throw new _node.default.Error(_node.default.Error.DUPLICATE_VALUE, 'A duplicate value for a field with unique values was provided');
      } else {
        throw error;
      }
    });
  } // Executes a count.


  async count(className, schema, query, readPreference, estimate = true) {
    debug('count');
    const values = [className];
    const where = buildWhereClause({
      schema,
      query,
      index: 2,
      caseInsensitive: false
    });
    values.push(...where.values);
    const wherePattern = where.pattern.length > 0 ? `WHERE ${where.pattern}` : '';
    let qs = '';

    if (where.pattern.length > 0 || !estimate) {
      qs = `SELECT count(*) FROM $1:name ${wherePattern}`;
    } else {
      qs = 'SELECT reltuples AS approximate_row_count FROM pg_class WHERE relname = $1';
    }

    return this._client.one(qs, values, a => {
      if (a.approximate_row_count != null) {
        return +a.approximate_row_count;
      } else {
        return +a.count;
      }
    }).catch(error => {
      if (error.code !== PostgresRelationDoesNotExistError) {
        throw error;
      }

      return 0;
    });
  }

  async distinct(className, schema, query, fieldName) {
    debug('distinct');
    let field = fieldName;
    let column = fieldName;
    const isNested = fieldName.indexOf('.') >= 0;

    if (isNested) {
      field = transformDotFieldToComponents(fieldName).join('->');
      column = fieldName.split('.')[0];
    }

    const isArrayField = schema.fields && schema.fields[fieldName] && schema.fields[fieldName].type === 'Array';
    const isPointerField = schema.fields && schema.fields[fieldName] && schema.fields[fieldName].type === 'Pointer';
    const values = [field, column, className];
    const where = buildWhereClause({
      schema,
      query,
      index: 4,
      caseInsensitive: false
    });
    values.push(...where.values);
    const wherePattern = where.pattern.length > 0 ? `WHERE ${where.pattern}` : '';
    const transformer = isArrayField ? 'jsonb_array_elements' : 'ON';
    let qs = `SELECT DISTINCT ${transformer}($1:name) $2:name FROM $3:name ${wherePattern}`;

    if (isNested) {
      qs = `SELECT DISTINCT ${transformer}($1:raw) $2:raw FROM $3:name ${wherePattern}`;
    }

    return this._client.any(qs, values).catch(error => {
      if (error.code === PostgresMissingColumnError) {
        return [];
      }

      throw error;
    }).then(results => {
      if (!isNested) {
        results = results.filter(object => object[field] !== null);
        return results.map(object => {
          if (!isPointerField) {
            return object[field];
          }

          return {
            __type: 'Pointer',
            className: schema.fields[fieldName].targetClass,
            objectId: object[field]
          };
        });
      }

      const child = fieldName.split('.')[1];
      return results.map(object => object[column][child]);
    }).then(results => results.map(object => this.postgresObjectToParseObject(className, object, schema)));
  }

  async aggregate(className, schema, pipeline, readPreference, hint, explain) {
    debug('aggregate');
    const values = [className];
    let index = 2;
    let columns = [];
    let countField = null;
    let groupValues = null;
    let wherePattern = '';
    let limitPattern = '';
    let skipPattern = '';
    let sortPattern = '';
    let groupPattern = '';

    for (let i = 0; i < pipeline.length; i += 1) {
      const stage = pipeline[i];

      if (stage.$group) {
        for (const field in stage.$group) {
          const value = stage.$group[field];

          if (value === null || value === undefined) {
            continue;
          }

          if (field === '_id' && typeof value === 'string' && value !== '') {
            columns.push(`$${index}:name AS "objectId"`);
            groupPattern = `GROUP BY $${index}:name`;
            values.push(transformAggregateField(value));
            index += 1;
            continue;
          }

          if (field === '_id' && typeof value === 'object' && Object.keys(value).length !== 0) {
            groupValues = value;
            const groupByFields = [];

            for (const alias in value) {
              if (typeof value[alias] === 'string' && value[alias]) {
                const source = transformAggregateField(value[alias]);

                if (!groupByFields.includes(`"${source}"`)) {
                  groupByFields.push(`"${source}"`);
                }

                values.push(source, alias);
                columns.push(`$${index}:name AS $${index + 1}:name`);
                index += 2;
              } else {
                const operation = Object.keys(value[alias])[0];
                const source = transformAggregateField(value[alias][operation]);

                if (mongoAggregateToPostgres[operation]) {
                  if (!groupByFields.includes(`"${source}"`)) {
                    groupByFields.push(`"${source}"`);
                  }

                  columns.push(`EXTRACT(${mongoAggregateToPostgres[operation]} FROM $${index}:name AT TIME ZONE 'UTC') AS $${index + 1}:name`);
                  values.push(source, alias);
                  index += 2;
                }
              }
            }

            groupPattern = `GROUP BY $${index}:raw`;
            values.push(groupByFields.join());
            index += 1;
            continue;
          }

          if (typeof value === 'object') {
            if (value.$sum) {
              if (typeof value.$sum === 'string') {
                columns.push(`SUM($${index}:name) AS $${index + 1}:name`);
                values.push(transformAggregateField(value.$sum), field);
                index += 2;
              } else {
                countField = field;
                columns.push(`COUNT(*) AS $${index}:name`);
                values.push(field);
                index += 1;
              }
            }

            if (value.$max) {
              columns.push(`MAX($${index}:name) AS $${index + 1}:name`);
              values.push(transformAggregateField(value.$max), field);
              index += 2;
            }

            if (value.$min) {
              columns.push(`MIN($${index}:name) AS $${index + 1}:name`);
              values.push(transformAggregateField(value.$min), field);
              index += 2;
            }

            if (value.$avg) {
              columns.push(`AVG($${index}:name) AS $${index + 1}:name`);
              values.push(transformAggregateField(value.$avg), field);
              index += 2;
            }
          }
        }
      } else {
        columns.push('*');
      }

      if (stage.$project) {
        if (columns.includes('*')) {
          columns = [];
        }

        for (const field in stage.$project) {
          const value = stage.$project[field];

          if (value === 1 || value === true) {
            columns.push(`$${index}:name`);
            values.push(field);
            index += 1;
          }
        }
      }

      if (stage.$match) {
        const patterns = [];
        const orOrAnd = Object.prototype.hasOwnProperty.call(stage.$match, '$or') ? ' OR ' : ' AND ';

        if (stage.$match.$or) {
          const collapse = {};
          stage.$match.$or.forEach(element => {
            for (const key in element) {
              collapse[key] = element[key];
            }
          });
          stage.$match = collapse;
        }

        for (const field in stage.$match) {
          const value = stage.$match[field];
          const matchPatterns = [];
          Object.keys(ParseToPosgresComparator).forEach(cmp => {
            if (value[cmp]) {
              const pgComparator = ParseToPosgresComparator[cmp];
              matchPatterns.push(`$${index}:name ${pgComparator} $${index + 1}`);
              values.push(field, toPostgresValue(value[cmp]));
              index += 2;
            }
          });

          if (matchPatterns.length > 0) {
            patterns.push(`(${matchPatterns.join(' AND ')})`);
          }

          if (schema.fields[field] && schema.fields[field].type && matchPatterns.length === 0) {
            patterns.push(`$${index}:name = $${index + 1}`);
            values.push(field, value);
            index += 2;
          }
        }

        wherePattern = patterns.length > 0 ? `WHERE ${patterns.join(` ${orOrAnd} `)}` : '';
      }

      if (stage.$limit) {
        limitPattern = `LIMIT $${index}`;
        values.push(stage.$limit);
        index += 1;
      }

      if (stage.$skip) {
        skipPattern = `OFFSET $${index}`;
        values.push(stage.$skip);
        index += 1;
      }

      if (stage.$sort) {
        const sort = stage.$sort;
        const keys = Object.keys(sort);
        const sorting = keys.map(key => {
          const transformer = sort[key] === 1 ? 'ASC' : 'DESC';
          const order = `$${index}:name ${transformer}`;
          index += 1;
          return order;
        }).join();
        values.push(...keys);
        sortPattern = sort !== undefined && sorting.length > 0 ? `ORDER BY ${sorting}` : '';
      }
    }

    if (groupPattern) {
      columns.forEach((e, i, a) => {
        if (e && e.trim() === '*') {
          a[i] = '';
        }
      });
    }

    const originalQuery = `SELECT ${columns.filter(Boolean).join()} FROM $1:name ${wherePattern} ${skipPattern} ${groupPattern} ${sortPattern} ${limitPattern}`;
    const qs = explain ? this.createExplainableQuery(originalQuery) : originalQuery;
    return this._client.any(qs, values).then(a => {
      if (explain) {
        return a;
      }

      const results = a.map(object => this.postgresObjectToParseObject(className, object, schema));
      results.forEach(result => {
        if (!Object.prototype.hasOwnProperty.call(result, 'objectId')) {
          result.objectId = null;
        }

        if (groupValues) {
          result.objectId = {};

          for (const key in groupValues) {
            result.objectId[key] = result[key];
            delete result[key];
          }
        }

        if (countField) {
          result[countField] = parseInt(result[countField], 10);
        }
      });
      return results;
    });
  }

  async performInitialization({
    VolatileClassesSchemas
  }) {
    // TODO: This method needs to be rewritten to make proper use of connections (@vitaly-t)
    debug('performInitialization');
    await this._ensureSchemaCollectionExists();
    const promises = VolatileClassesSchemas.map(schema => {
      return this.createTable(schema.className, schema).catch(err => {
        if (err.code === PostgresDuplicateRelationError || err.code === _node.default.Error.INVALID_CLASS_NAME) {
          return Promise.resolve();
        }

        throw err;
      }).then(() => this.schemaUpgrade(schema.className, schema));
    });
    promises.push(this._listenToSchema());
    return Promise.all(promises).then(() => {
      return this._client.tx('perform-initialization', async t => {
        await t.none(_sql.default.misc.jsonObjectSetKeys);
        await t.none(_sql.default.array.add);
        await t.none(_sql.default.array.addUnique);
        await t.none(_sql.default.array.remove);
        await t.none(_sql.default.array.containsAll);
        await t.none(_sql.default.array.containsAllRegex);
        await t.none(_sql.default.array.contains);
        return t.ctx;
      });
    }).then(ctx => {
      debug(`initializationDone in ${ctx.duration}`);
    }).catch(error => {
      /* eslint-disable no-console */
      console.error(error);
    });
  }

  async createIndexes(className, indexes, conn) {
    return (conn || this._client).tx(t => t.batch(indexes.map(i => {
      return t.none('CREATE INDEX IF NOT EXISTS $1:name ON $2:name ($3:name)', [i.name, className, i.key]);
    })));
  }

  async createIndexesIfNeeded(className, fieldName, type, conn) {
    await (conn || this._client).none('CREATE INDEX IF NOT EXISTS $1:name ON $2:name ($3:name)', [fieldName, className, type]);
  }

  async dropIndexes(className, indexes, conn) {
    const queries = indexes.map(i => ({
      query: 'DROP INDEX $1:name',
      values: i
    }));
    await (conn || this._client).tx(t => t.none(this._pgp.helpers.concat(queries)));
  }

  async getIndexes(className) {
    const qs = 'SELECT * FROM pg_indexes WHERE tablename = ${className}';
    return this._client.any(qs, {
      className
    });
  }

  async updateSchemaWithIndexes() {
    return Promise.resolve();
  } // Used for testing purposes


  async updateEstimatedCount(className) {
    return this._client.none('ANALYZE $1:name', [className]);
  }

  async createTransactionalSession() {
    return new Promise(resolve => {
      const transactionalSession = {};
      transactionalSession.result = this._client.tx(t => {
        transactionalSession.t = t;
        transactionalSession.promise = new Promise(resolve => {
          transactionalSession.resolve = resolve;
        });
        transactionalSession.batch = [];
        resolve(transactionalSession);
        return transactionalSession.promise;
      });
    });
  }

  commitTransactionalSession(transactionalSession) {
    transactionalSession.resolve(transactionalSession.t.batch(transactionalSession.batch));
    return transactionalSession.result;
  }

  abortTransactionalSession(transactionalSession) {
    const result = transactionalSession.result.catch();
    transactionalSession.batch.push(Promise.reject());
    transactionalSession.resolve(transactionalSession.t.batch(transactionalSession.batch));
    return result;
  }

  async ensureIndex(className, schema, fieldNames, indexName, caseInsensitive = false, options = {}) {
    const conn = options.conn !== undefined ? options.conn : this._client;
    const defaultIndexName = `parse_default_${fieldNames.sort().join('_')}`;
    const indexNameOptions = indexName != null ? {
      name: indexName
    } : {
      name: defaultIndexName
    };
    const constraintPatterns = caseInsensitive ? fieldNames.map((fieldName, index) => `lower($${index + 3}:name) varchar_pattern_ops`) : fieldNames.map((fieldName, index) => `$${index + 3}:name`);
    const qs = `CREATE INDEX IF NOT EXISTS $1:name ON $2:name (${constraintPatterns.join()})`;
    await conn.none(qs, [indexNameOptions.name, className, ...fieldNames]).catch(error => {
      if (error.code === PostgresDuplicateRelationError && error.message.includes(indexNameOptions.name)) {// Index already exists. Ignore error.
      } else if (error.code === PostgresUniqueIndexViolationError && error.message.includes(indexNameOptions.name)) {
        // Cast the error into the proper parse error
        throw new _node.default.Error(_node.default.Error.DUPLICATE_VALUE, 'A duplicate value for a field with unique values was provided');
      } else {
        throw error;
      }
    });
  }

}

exports.PostgresStorageAdapter = PostgresStorageAdapter;

function convertPolygonToSQL(polygon) {
  if (polygon.length < 3) {
    throw new _node.default.Error(_node.default.Error.INVALID_JSON, `Polygon must have at least 3 values`);
  }

  if (polygon[0][0] !== polygon[polygon.length - 1][0] || polygon[0][1] !== polygon[polygon.length - 1][1]) {
    polygon.push(polygon[0]);
  }

  const unique = polygon.filter((item, index, ar) => {
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
    throw new _node.default.Error(_node.default.Error.INTERNAL_SERVER_ERROR, 'GeoJSON: Loop must have at least 3 different vertices');
  }

  const points = polygon.map(point => {
    _node.default.GeoPoint._validate(parseFloat(point[1]), parseFloat(point[0]));

    return `(${point[1]}, ${point[0]})`;
  }).join(', ');
  return `(${points})`;
}

function removeWhiteSpace(regex) {
  if (!regex.endsWith('\n')) {
    regex += '\n';
  } // remove non escaped comments


  return regex.replace(/([^\\])#.*\n/gim, '$1') // remove lines starting with a comment
  .replace(/^#.*\n/gim, '') // remove non escaped whitespace
  .replace(/([^\\])\s+/gim, '$1') // remove whitespace at the beginning of a line
  .replace(/^\s+/, '').trim();
}

function processRegexPattern(s) {
  if (s && s.startsWith('^')) {
    // regex for startsWith
    return '^' + literalizeRegexPart(s.slice(1));
  } else if (s && s.endsWith('$')) {
    // regex for endsWith
    return literalizeRegexPart(s.slice(0, s.length - 1)) + '$';
  } // regex for contains


  return literalizeRegexPart(s);
}

function isStartsWithRegex(value) {
  if (!value || typeof value !== 'string' || !value.startsWith('^')) {
    return false;
  }

  const matches = value.match(/\^\\Q.*\\E/);
  return !!matches;
}

function isAllValuesRegexOrNone(values) {
  if (!values || !Array.isArray(values) || values.length === 0) {
    return true;
  }

  const firstValuesIsRegex = isStartsWithRegex(values[0].$regex);

  if (values.length === 1) {
    return firstValuesIsRegex;
  }

  for (let i = 1, length = values.length; i < length; ++i) {
    if (firstValuesIsRegex !== isStartsWithRegex(values[i].$regex)) {
      return false;
    }
  }

  return true;
}

function isAnyValueRegexStartsWith(values) {
  return values.some(function (value) {
    return isStartsWithRegex(value.$regex);
  });
}

function createLiteralRegex(remaining) {
  return remaining.split('').map(c => {
    const regex = RegExp('[0-9 ]|\\p{L}', 'u'); // Support all unicode letter chars

    if (c.match(regex) !== null) {
      // don't escape alphanumeric characters
      return c;
    } // escape everything else (single quotes with single quotes, everything else with a backslash)


    return c === `'` ? `''` : `\\${c}`;
  }).join('');
}

function literalizeRegexPart(s) {
  const matcher1 = /\\Q((?!\\E).*)\\E$/;
  const result1 = s.match(matcher1);

  if (result1 && result1.length > 1 && result1.index > -1) {
    // process regex that has a beginning and an end specified for the literal text
    const prefix = s.substr(0, result1.index);
    const remaining = result1[1];
    return literalizeRegexPart(prefix) + createLiteralRegex(remaining);
  } // process regex that has a beginning specified for the literal text


  const matcher2 = /\\Q((?!\\E).*)$/;
  const result2 = s.match(matcher2);

  if (result2 && result2.length > 1 && result2.index > -1) {
    const prefix = s.substr(0, result2.index);
    const remaining = result2[1];
    return literalizeRegexPart(prefix) + createLiteralRegex(remaining);
  } // remove all instances of \Q and \E from the remaining text & escape single quotes


  return s.replace(/([^\\])(\\E)/, '$1').replace(/([^\\])(\\Q)/, '$1').replace(/^\\E/, '').replace(/^\\Q/, '').replace(/([^'])'/, `$1''`).replace(/^'([^'])/, `''$1`);
}

var GeoPointCoder = {
  isValidJSON(value) {
    return typeof value === 'object' && value !== null && value.__type === 'GeoPoint';
  }

};
var _default = PostgresStorageAdapter;
exports.default = _default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9BZGFwdGVycy9TdG9yYWdlL1Bvc3RncmVzL1Bvc3RncmVzU3RvcmFnZUFkYXB0ZXIuanMiXSwibmFtZXMiOlsiUG9zdGdyZXNSZWxhdGlvbkRvZXNOb3RFeGlzdEVycm9yIiwiUG9zdGdyZXNEdXBsaWNhdGVSZWxhdGlvbkVycm9yIiwiUG9zdGdyZXNEdXBsaWNhdGVDb2x1bW5FcnJvciIsIlBvc3RncmVzTWlzc2luZ0NvbHVtbkVycm9yIiwiUG9zdGdyZXNEdXBsaWNhdGVPYmplY3RFcnJvciIsIlBvc3RncmVzVW5pcXVlSW5kZXhWaW9sYXRpb25FcnJvciIsImxvZ2dlciIsInJlcXVpcmUiLCJkZWJ1ZyIsImFyZ3MiLCJhcmd1bWVudHMiLCJjb25jYXQiLCJzbGljZSIsImxlbmd0aCIsImxvZyIsImdldExvZ2dlciIsImFwcGx5IiwicGFyc2VUeXBlVG9Qb3N0Z3Jlc1R5cGUiLCJ0eXBlIiwiY29udGVudHMiLCJKU09OIiwic3RyaW5naWZ5IiwiUGFyc2VUb1Bvc2dyZXNDb21wYXJhdG9yIiwiJGd0IiwiJGx0IiwiJGd0ZSIsIiRsdGUiLCJtb25nb0FnZ3JlZ2F0ZVRvUG9zdGdyZXMiLCIkZGF5T2ZNb250aCIsIiRkYXlPZldlZWsiLCIkZGF5T2ZZZWFyIiwiJGlzb0RheU9mV2VlayIsIiRpc29XZWVrWWVhciIsIiRob3VyIiwiJG1pbnV0ZSIsIiRzZWNvbmQiLCIkbWlsbGlzZWNvbmQiLCIkbW9udGgiLCIkd2VlayIsIiR5ZWFyIiwidG9Qb3N0Z3Jlc1ZhbHVlIiwidmFsdWUiLCJfX3R5cGUiLCJpc28iLCJuYW1lIiwidHJhbnNmb3JtVmFsdWUiLCJvYmplY3RJZCIsImVtcHR5Q0xQUyIsIk9iamVjdCIsImZyZWV6ZSIsImZpbmQiLCJnZXQiLCJjb3VudCIsImNyZWF0ZSIsInVwZGF0ZSIsImRlbGV0ZSIsImFkZEZpZWxkIiwicHJvdGVjdGVkRmllbGRzIiwiZGVmYXVsdENMUFMiLCJ0b1BhcnNlU2NoZW1hIiwic2NoZW1hIiwiY2xhc3NOYW1lIiwiZmllbGRzIiwiX2hhc2hlZF9wYXNzd29yZCIsIl93cGVybSIsIl9ycGVybSIsImNscHMiLCJjbGFzc0xldmVsUGVybWlzc2lvbnMiLCJpbmRleGVzIiwidG9Qb3N0Z3Jlc1NjaGVtYSIsIl9wYXNzd29yZF9oaXN0b3J5IiwiaGFuZGxlRG90RmllbGRzIiwib2JqZWN0Iiwia2V5cyIsImZvckVhY2giLCJmaWVsZE5hbWUiLCJpbmRleE9mIiwiY29tcG9uZW50cyIsInNwbGl0IiwiZmlyc3QiLCJzaGlmdCIsImN1cnJlbnRPYmoiLCJuZXh0IiwiX19vcCIsInVuZGVmaW5lZCIsInRyYW5zZm9ybURvdEZpZWxkVG9Db21wb25lbnRzIiwibWFwIiwiY21wdCIsImluZGV4IiwidHJhbnNmb3JtRG90RmllbGQiLCJqb2luIiwidHJhbnNmb3JtQWdncmVnYXRlRmllbGQiLCJzdWJzdHIiLCJ2YWxpZGF0ZUtleXMiLCJrZXkiLCJpbmNsdWRlcyIsIlBhcnNlIiwiRXJyb3IiLCJJTlZBTElEX05FU1RFRF9LRVkiLCJqb2luVGFibGVzRm9yU2NoZW1hIiwibGlzdCIsImZpZWxkIiwicHVzaCIsImJ1aWxkV2hlcmVDbGF1c2UiLCJxdWVyeSIsImNhc2VJbnNlbnNpdGl2ZSIsInBhdHRlcm5zIiwidmFsdWVzIiwic29ydHMiLCJpc0FycmF5RmllbGQiLCJpbml0aWFsUGF0dGVybnNMZW5ndGgiLCJmaWVsZFZhbHVlIiwiJGV4aXN0cyIsImF1dGhEYXRhTWF0Y2giLCJtYXRjaCIsIiRpbiIsIiRyZWdleCIsIk1BWF9JTlRfUExVU19PTkUiLCJjbGF1c2VzIiwiY2xhdXNlVmFsdWVzIiwic3ViUXVlcnkiLCJjbGF1c2UiLCJwYXR0ZXJuIiwib3JPckFuZCIsIm5vdCIsIiRuZSIsImNvbnN0cmFpbnRGaWVsZE5hbWUiLCJwb2ludCIsImxvbmdpdHVkZSIsImxhdGl0dWRlIiwiJGVxIiwiaXNJbk9yTmluIiwiQXJyYXkiLCJpc0FycmF5IiwiJG5pbiIsImluUGF0dGVybnMiLCJhbGxvd051bGwiLCJsaXN0RWxlbSIsImxpc3RJbmRleCIsImNyZWF0ZUNvbnN0cmFpbnQiLCJiYXNlQXJyYXkiLCJub3RJbiIsIl8iLCJmbGF0TWFwIiwiZWx0IiwiSU5WQUxJRF9KU09OIiwiJGFsbCIsImlzQW55VmFsdWVSZWdleFN0YXJ0c1dpdGgiLCJpc0FsbFZhbHVlc1JlZ2V4T3JOb25lIiwiaSIsInByb2Nlc3NSZWdleFBhdHRlcm4iLCJzdWJzdHJpbmciLCIkY29udGFpbmVkQnkiLCJhcnIiLCIkdGV4dCIsInNlYXJjaCIsIiRzZWFyY2giLCJsYW5ndWFnZSIsIiR0ZXJtIiwiJGxhbmd1YWdlIiwiJGNhc2VTZW5zaXRpdmUiLCIkZGlhY3JpdGljU2Vuc2l0aXZlIiwiJG5lYXJTcGhlcmUiLCJkaXN0YW5jZSIsIiRtYXhEaXN0YW5jZSIsImRpc3RhbmNlSW5LTSIsIiR3aXRoaW4iLCIkYm94IiwiYm94IiwibGVmdCIsImJvdHRvbSIsInJpZ2h0IiwidG9wIiwiJGdlb1dpdGhpbiIsIiRjZW50ZXJTcGhlcmUiLCJjZW50ZXJTcGhlcmUiLCJHZW9Qb2ludCIsIkdlb1BvaW50Q29kZXIiLCJpc1ZhbGlkSlNPTiIsIl92YWxpZGF0ZSIsImlzTmFOIiwiJHBvbHlnb24iLCJwb2x5Z29uIiwicG9pbnRzIiwiY29vcmRpbmF0ZXMiLCIkZ2VvSW50ZXJzZWN0cyIsIiRwb2ludCIsInJlZ2V4Iiwib3BlcmF0b3IiLCJvcHRzIiwiJG9wdGlvbnMiLCJyZW1vdmVXaGl0ZVNwYWNlIiwiY29udmVydFBvbHlnb25Ub1NRTCIsImNtcCIsInBnQ29tcGFyYXRvciIsInBvc3RncmVzVmFsdWUiLCJjYXN0VHlwZSIsIk9QRVJBVElPTl9GT1JCSURERU4iLCJQb3N0Z3Jlc1N0b3JhZ2VBZGFwdGVyIiwiY29uc3RydWN0b3IiLCJ1cmkiLCJjb2xsZWN0aW9uUHJlZml4IiwiZGF0YWJhc2VPcHRpb25zIiwiX2NvbGxlY3Rpb25QcmVmaXgiLCJlbmFibGVTY2hlbWFIb29rcyIsImNsaWVudCIsInBncCIsIl9jbGllbnQiLCJfb25jaGFuZ2UiLCJfcGdwIiwiX3V1aWQiLCJjYW5Tb3J0T25Kb2luVGFibGVzIiwid2F0Y2giLCJjYWxsYmFjayIsImNyZWF0ZUV4cGxhaW5hYmxlUXVlcnkiLCJhbmFseXplIiwiaGFuZGxlU2h1dGRvd24iLCJfc3RyZWFtIiwiZG9uZSIsIiRwb29sIiwiZW5kIiwiX2xpc3RlblRvU2NoZW1hIiwiY29ubmVjdCIsImRpcmVjdCIsIm9uIiwiZGF0YSIsInBheWxvYWQiLCJwYXJzZSIsInNlbmRlcklkIiwibm9uZSIsIl9ub3RpZnlTY2hlbWFDaGFuZ2UiLCJjYXRjaCIsImVycm9yIiwiY29uc29sZSIsIl9lbnN1cmVTY2hlbWFDb2xsZWN0aW9uRXhpc3RzIiwiY29ubiIsImNvZGUiLCJjbGFzc0V4aXN0cyIsIm9uZSIsImEiLCJleGlzdHMiLCJzZXRDbGFzc0xldmVsUGVybWlzc2lvbnMiLCJDTFBzIiwidGFzayIsInQiLCJzZXRJbmRleGVzV2l0aFNjaGVtYUZvcm1hdCIsInN1Ym1pdHRlZEluZGV4ZXMiLCJleGlzdGluZ0luZGV4ZXMiLCJzZWxmIiwiUHJvbWlzZSIsInJlc29sdmUiLCJfaWRfIiwiX2lkIiwiZGVsZXRlZEluZGV4ZXMiLCJpbnNlcnRlZEluZGV4ZXMiLCJJTlZBTElEX1FVRVJZIiwicHJvdG90eXBlIiwiaGFzT3duUHJvcGVydHkiLCJjYWxsIiwidHgiLCJjcmVhdGVJbmRleGVzIiwiZHJvcEluZGV4ZXMiLCJjcmVhdGVDbGFzcyIsInBhcnNlU2NoZW1hIiwiY3JlYXRlVGFibGUiLCJlcnIiLCJkZXRhaWwiLCJEVVBMSUNBVEVfVkFMVUUiLCJ2YWx1ZXNBcnJheSIsInBhdHRlcm5zQXJyYXkiLCJhc3NpZ24iLCJfZW1haWxfdmVyaWZ5X3Rva2VuX2V4cGlyZXNfYXQiLCJfZW1haWxfdmVyaWZ5X3Rva2VuIiwiX2FjY291bnRfbG9ja291dF9leHBpcmVzX2F0IiwiX2ZhaWxlZF9sb2dpbl9jb3VudCIsIl9wZXJpc2hhYmxlX3Rva2VuIiwiX3BlcmlzaGFibGVfdG9rZW5fZXhwaXJlc19hdCIsIl9wYXNzd29yZF9jaGFuZ2VkX2F0IiwicmVsYXRpb25zIiwicGFyc2VUeXBlIiwicXMiLCJiYXRjaCIsImpvaW5UYWJsZSIsInNjaGVtYVVwZ3JhZGUiLCJjb2x1bW5zIiwiY29sdW1uX25hbWUiLCJuZXdDb2x1bW5zIiwiZmlsdGVyIiwiaXRlbSIsImFkZEZpZWxkSWZOb3RFeGlzdHMiLCJwb3N0Z3Jlc1R5cGUiLCJyZXN1bHQiLCJhbnkiLCJwYXRoIiwiZGVsZXRlQ2xhc3MiLCJvcGVyYXRpb25zIiwicmVzcG9uc2UiLCJoZWxwZXJzIiwidGhlbiIsImRlbGV0ZUFsbENsYXNzZXMiLCJub3ciLCJEYXRlIiwiZ2V0VGltZSIsInJlc3VsdHMiLCJqb2lucyIsInJlZHVjZSIsImNsYXNzZXMiLCJxdWVyaWVzIiwiZGVsZXRlRmllbGRzIiwiZmllbGROYW1lcyIsImlkeCIsImdldEFsbENsYXNzZXMiLCJyb3ciLCJnZXRDbGFzcyIsImNyZWF0ZU9iamVjdCIsInRyYW5zYWN0aW9uYWxTZXNzaW9uIiwiY29sdW1uc0FycmF5IiwiZ2VvUG9pbnRzIiwicHJvdmlkZXIiLCJwb3AiLCJpbml0aWFsVmFsdWVzIiwidmFsIiwidGVybWluYXRpb24iLCJnZW9Qb2ludHNJbmplY3RzIiwibCIsImNvbHVtbnNQYXR0ZXJuIiwiY29sIiwidmFsdWVzUGF0dGVybiIsInByb21pc2UiLCJvcHMiLCJ1bmRlcmx5aW5nRXJyb3IiLCJjb25zdHJhaW50IiwibWF0Y2hlcyIsInVzZXJJbmZvIiwiZHVwbGljYXRlZF9maWVsZCIsImRlbGV0ZU9iamVjdHNCeVF1ZXJ5Iiwid2hlcmUiLCJPQkpFQ1RfTk9UX0ZPVU5EIiwiZmluZE9uZUFuZFVwZGF0ZSIsInVwZGF0ZU9iamVjdHNCeVF1ZXJ5IiwidXBkYXRlUGF0dGVybnMiLCJvcmlnaW5hbFVwZGF0ZSIsImRvdE5vdGF0aW9uT3B0aW9ucyIsImdlbmVyYXRlIiwianNvbmIiLCJsYXN0S2V5IiwiZmllbGROYW1lSW5kZXgiLCJzdHIiLCJhbW91bnQiLCJvYmplY3RzIiwia2V5c1RvSW5jcmVtZW50IiwiayIsImluY3JlbWVudFBhdHRlcm5zIiwiYyIsImtleXNUb0RlbGV0ZSIsImRlbGV0ZVBhdHRlcm5zIiwicCIsInVwZGF0ZU9iamVjdCIsImV4cGVjdGVkVHlwZSIsInJlamVjdCIsIndoZXJlQ2xhdXNlIiwidXBzZXJ0T25lT2JqZWN0IiwiY3JlYXRlVmFsdWUiLCJza2lwIiwibGltaXQiLCJzb3J0IiwiZXhwbGFpbiIsImhhc0xpbWl0IiwiaGFzU2tpcCIsIndoZXJlUGF0dGVybiIsImxpbWl0UGF0dGVybiIsInNraXBQYXR0ZXJuIiwic29ydFBhdHRlcm4iLCJzb3J0Q29weSIsInNvcnRpbmciLCJ0cmFuc2Zvcm1LZXkiLCJtZW1vIiwib3JpZ2luYWxRdWVyeSIsInBvc3RncmVzT2JqZWN0VG9QYXJzZU9iamVjdCIsInRhcmdldENsYXNzIiwieSIsIngiLCJjb29yZHMiLCJwYXJzZUZsb2F0IiwiY3JlYXRlZEF0IiwidG9JU09TdHJpbmciLCJ1cGRhdGVkQXQiLCJleHBpcmVzQXQiLCJlbnN1cmVVbmlxdWVuZXNzIiwiY29uc3RyYWludE5hbWUiLCJjb25zdHJhaW50UGF0dGVybnMiLCJtZXNzYWdlIiwicmVhZFByZWZlcmVuY2UiLCJlc3RpbWF0ZSIsImFwcHJveGltYXRlX3Jvd19jb3VudCIsImRpc3RpbmN0IiwiY29sdW1uIiwiaXNOZXN0ZWQiLCJpc1BvaW50ZXJGaWVsZCIsInRyYW5zZm9ybWVyIiwiY2hpbGQiLCJhZ2dyZWdhdGUiLCJwaXBlbGluZSIsImhpbnQiLCJjb3VudEZpZWxkIiwiZ3JvdXBWYWx1ZXMiLCJncm91cFBhdHRlcm4iLCJzdGFnZSIsIiRncm91cCIsImdyb3VwQnlGaWVsZHMiLCJhbGlhcyIsInNvdXJjZSIsIm9wZXJhdGlvbiIsIiRzdW0iLCIkbWF4IiwiJG1pbiIsIiRhdmciLCIkcHJvamVjdCIsIiRtYXRjaCIsIiRvciIsImNvbGxhcHNlIiwiZWxlbWVudCIsIm1hdGNoUGF0dGVybnMiLCIkbGltaXQiLCIkc2tpcCIsIiRzb3J0Iiwib3JkZXIiLCJlIiwidHJpbSIsIkJvb2xlYW4iLCJwYXJzZUludCIsInBlcmZvcm1Jbml0aWFsaXphdGlvbiIsIlZvbGF0aWxlQ2xhc3Nlc1NjaGVtYXMiLCJwcm9taXNlcyIsIklOVkFMSURfQ0xBU1NfTkFNRSIsImFsbCIsInNxbCIsIm1pc2MiLCJqc29uT2JqZWN0U2V0S2V5cyIsImFycmF5IiwiYWRkIiwiYWRkVW5pcXVlIiwicmVtb3ZlIiwiY29udGFpbnNBbGwiLCJjb250YWluc0FsbFJlZ2V4IiwiY29udGFpbnMiLCJjdHgiLCJkdXJhdGlvbiIsImNyZWF0ZUluZGV4ZXNJZk5lZWRlZCIsImdldEluZGV4ZXMiLCJ1cGRhdGVTY2hlbWFXaXRoSW5kZXhlcyIsInVwZGF0ZUVzdGltYXRlZENvdW50IiwiY3JlYXRlVHJhbnNhY3Rpb25hbFNlc3Npb24iLCJjb21taXRUcmFuc2FjdGlvbmFsU2Vzc2lvbiIsImFib3J0VHJhbnNhY3Rpb25hbFNlc3Npb24iLCJlbnN1cmVJbmRleCIsImluZGV4TmFtZSIsIm9wdGlvbnMiLCJkZWZhdWx0SW5kZXhOYW1lIiwiaW5kZXhOYW1lT3B0aW9ucyIsInVuaXF1ZSIsImFyIiwiZm91bmRJbmRleCIsInB0IiwiSU5URVJOQUxfU0VSVkVSX0VSUk9SIiwiZW5kc1dpdGgiLCJyZXBsYWNlIiwicyIsInN0YXJ0c1dpdGgiLCJsaXRlcmFsaXplUmVnZXhQYXJ0IiwiaXNTdGFydHNXaXRoUmVnZXgiLCJmaXJzdFZhbHVlc0lzUmVnZXgiLCJzb21lIiwiY3JlYXRlTGl0ZXJhbFJlZ2V4IiwicmVtYWluaW5nIiwiUmVnRXhwIiwibWF0Y2hlcjEiLCJyZXN1bHQxIiwicHJlZml4IiwibWF0Y2hlcjIiLCJyZXN1bHQyIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQ0E7O0FBRUE7O0FBRUE7O0FBRUE7O0FBQ0E7O0FBZ0JBOzs7Ozs7Ozs7O0FBZEEsTUFBTUEsaUNBQWlDLEdBQUcsT0FBMUM7QUFDQSxNQUFNQyw4QkFBOEIsR0FBRyxPQUF2QztBQUNBLE1BQU1DLDRCQUE0QixHQUFH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QUFNQyxPQUFZLEdBQUdiLENBQUMsQ0FBQ2pXLEtBQUYsQ0FBUTZXLFFBQVIsQ0FBckI7O0FBQ0EsTUFBSUMsT0FBTyxJQUFJQSxPQUFPLENBQUNuZCxNQUFSLEdBQWlCLENBQTVCLElBQWlDbWQsT0FBTyxDQUFDeFksS0FBUixHQUFnQixDQUFDLENBQXRELEVBQXlEO0FBQ3ZELFVBQU1zWSxNQUFNLEdBQUdYLENBQUMsQ0FBQ3ZYLE1BQUYsQ0FBUyxDQUFULEVBQVlvWSxPQUFPLENBQUN4WSxLQUFwQixDQUFmO0FBQ0EsVUFBTWtZLFNBQVMsR0FBR00sT0FBTyxDQUFDLENBQUQsQ0FBekI7QUFFQSxXQUFPWCxtQkFBbUIsQ0FBQ1MsTUFBRCxDQUFuQixHQUE4Qkwsa0JBQWtCLENBQUNDLFNBQUQsQ0FBdkQ7QUFDRCxHQW5CcUMsQ0FxQnRDOzs7QUFDQSxTQUFPUCxDQUFDLENBQ0xELE9BREksQ0FDSSxjQURKLEVBQ29CLElBRHBCLEVBRUpBLE9BRkksQ0FFSSxjQUZKLEVBRW9CLElBRnBCLEVBR0pBLE9BSEksQ0FHSSxNQUhKLEVBR1ksRUFIWixFQUlKQSxPQUpJLENBSUksTUFKSixFQUlZLEVBSlosRUFLSkEsT0FMSSxDQUtJLFNBTEosRUFLZ0IsTUFMaEIsRUFNSkEsT0FOSSxDQU1JLFVBTkosRUFNaUIsTUFOakIsQ0FBUDtBQU9EOztBQUVELElBQUlqUyxhQUFhLEdBQUc7QUFDbEJDLEVBQUFBLFdBQVcsQ0FBQ3pJLEtBQUQsRUFBUTtBQUNqQixXQUFPLE9BQU9BLEtBQVAsS0FBaUIsUUFBakIsSUFBNkJBLEtBQUssS0FBSyxJQUF2QyxJQUErQ0EsS0FBSyxDQUFDQyxNQUFOLEtBQWlCLFVBQXZFO0FBQ0Q7O0FBSGlCLENBQXBCO2VBTWU0SixzQiIsInNvdXJjZXNDb250ZW50IjpbIi8vIEBmbG93XG5pbXBvcnQgeyBjcmVhdGVDbGllbnQgfSBmcm9tICcuL1Bvc3RncmVzQ2xpZW50Jztcbi8vIEBmbG93LWRpc2FibGUtbmV4dFxuaW1wb3J0IFBhcnNlIGZyb20gJ3BhcnNlL25vZGUnO1xuLy8gQGZsb3ctZGlzYWJsZS1uZXh0XG5pbXBvcnQgXyBmcm9tICdsb2Rhc2gnO1xuLy8gQGZsb3ctZGlzYWJsZS1uZXh0XG5pbXBvcnQgeyB2NCBhcyB1dWlkdjQgfSBmcm9tICd1dWlkJztcbmltcG9ydCBzcWwgZnJvbSAnLi9zcWwnO1xuXG5jb25zdCBQb3N0Z3Jlc1JlbGF0aW9uRG9lc05vdEV4aXN0RXJyb3IgPSAnNDJQMDEnO1xuY29uc3QgUG9zdGdyZXNEdXBsaWNhdGVSZWxhdGlvbkVycm9yID0gJzQyUDA3JztcbmNvbnN0IFBvc3RncmVzRHVwbGljYXRlQ29sdW1uRXJyb3IgPSAnNDI3MDEnO1xuY29uc3QgUG9zdGdyZXNNaXNzaW5nQ29sdW1uRXJyb3IgPSAnNDI3MDMnO1xuY29uc3QgUG9zdGdyZXNEdXBsaWNhdGVPYmplY3RFcnJvciA9ICc0MjcxMCc7XG5jb25zdCBQb3N0Z3Jlc1VuaXF1ZUluZGV4VmlvbGF0aW9uRXJyb3IgPSAnMjM1MDUnO1xuY29uc3QgbG9nZ2VyID0gcmVxdWlyZSgnLi4vLi4vLi4vbG9nZ2VyJyk7XG5cbmNvbnN0IGRlYnVnID0gZnVuY3Rpb24gKC4uLmFyZ3M6IGFueSkge1xuICBhcmdzID0gWydQRzogJyArIGFyZ3VtZW50c1swXV0uY29uY2F0KGFyZ3Muc2xpY2UoMSwgYXJncy5sZW5ndGgpKTtcbiAgY29uc3QgbG9nID0gbG9nZ2VyLmdldExvZ2dlcigpO1xuICBsb2cuZGVidWcuYXBwbHkobG9nLCBhcmdzKTtcbn07XG5cbmltcG9ydCB7IFN0b3JhZ2VBZGFwdGVyIH0gZnJvbSAnLi4vU3RvcmFnZUFkYXB0ZXInO1xuaW1wb3J0IHR5cGUgeyBTY2hlbWFUeXBlLCBRdWVyeVR5cGUsIFF1ZXJ5T3B0aW9ucyB9IGZyb20gJy4uL1N0b3JhZ2VBZGFwdGVyJztcblxuY29uc3QgcGFyc2VUeXBlVG9Qb3N0Z3Jlc1R5cGUgPSB0eXBlID0+IHtcbiAgc3dpdGNoICh0eXBlLnR5cGUpIHtcbiAgICBjYXNlICdTdHJpbmcnOlxuICAgICAgcmV0dXJuICd0ZXh0JztcbiAgICBjYXNlICdEYXRlJzpcbiAgICAgIHJldHVybiAndGltZXN0YW1wIHdpdGggdGltZSB6b25lJztcbiAgICBjYXNlICdPYmplY3QnOlxuICAgICAgcmV0dXJuICdqc29uYic7XG4gICAgY2FzZSAnRmlsZSc6XG4gICAgICByZXR1cm4gJ3RleHQnO1xuICAgIGNhc2UgJ0Jvb2xlYW4nOlxuICAgICAgcmV0dXJuICdib29sZWFuJztcbiAgICBjYXNlICdQb2ludGVyJzpcbiAgICAgIHJldHVybiAndGV4dCc7XG4gICAgY2FzZSAnTnVtYmVyJzpcbiAgICAgIHJldHVybiAnZG91YmxlIHByZWNpc2lvbic7XG4gICAgY2FzZSAnR2VvUG9pbnQnOlxuICAgICAgcmV0dXJuICdwb2ludCc7XG4gICAgY2FzZSAnQnl0ZXMnOlxuICAgICAgcmV0dXJuICdqc29uYic7XG4gICAgY2FzZSAnUG9seWdvbic6XG4gICAgICByZXR1cm4gJ3BvbHlnb24nO1xuICAgIGNhc2UgJ0FycmF5JzpcbiAgICAgIGlmICh0eXBlLmNvbnRlbnRzICYmIHR5cGUuY29udGVudHMudHlwZSA9PT0gJ1N0cmluZycpIHtcbiAgICAgICAgcmV0dXJuICd0ZXh0W10nO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuICdqc29uYic7XG4gICAgICB9XG4gICAgZGVmYXVsdDpcbiAgICAgIHRocm93IGBubyB0eXBlIGZvciAke0pTT04uc3RyaW5naWZ5KHR5cGUpfSB5ZXRgO1xuICB9XG59O1xuXG5jb25zdCBQYXJzZVRvUG9zZ3Jlc0NvbXBhcmF0b3IgPSB7XG4gICRndDogJz4nLFxuICAkbHQ6ICc8JyxcbiAgJGd0ZTogJz49JyxcbiAgJGx0ZTogJzw9Jyxcbn07XG5cbmNvbnN0IG1vbmdvQWdncmVnYXRlVG9Qb3N0Z3JlcyA9IHtcbiAgJGRheU9mTW9udGg6ICdEQVknLFxuICAkZGF5T2ZXZWVrOiAnRE9XJyxcbiAgJGRheU9mWWVhcjogJ0RPWScsXG4gICRpc29EYXlPZldlZWs6ICdJU09ET1cnLFxuICAkaXNvV2Vla1llYXI6ICdJU09ZRUFSJyxcbiAgJGhvdXI6ICdIT1VSJyxcbiAgJG1pbnV0ZTogJ01JTlVURScsXG4gICRzZWNvbmQ6ICdTRUNPTkQnLFxuICAkbWlsbGlzZWNvbmQ6ICdNSUxMSVNFQ09ORFMnLFxuICAkbW9udGg6ICdNT05USCcsXG4gICR3ZWVrOiAnV0VFSycsXG4gICR5ZWFyOiAnWUVBUicsXG59O1xuXG5jb25zdCB0b1Bvc3RncmVzVmFsdWUgPSB2YWx1ZSA9PiB7XG4gIGlmICh0eXBlb2YgdmFsdWUgPT09ICdvYmplY3QnKSB7XG4gICAgaWYgKHZhbHVlLl9fdHlwZSA9PT0gJ0RhdGUnKSB7XG4gICAgICByZXR1cm4gdmFsdWUuaXNvO1xuICAgIH1cbiAgICBpZiAodmFsdWUuX190eXBlID09PSAnRmlsZScpIHtcbiAgICAgIHJldHVybiB2YWx1ZS5uYW1lO1xuICAgIH1cbiAgfVxuICByZXR1cm4gdmFsdWU7XG59O1xuXG5jb25zdCB0cmFuc2Zvcm1WYWx1ZSA9IHZhbHVlID0+IHtcbiAgaWYgKHR5cGVvZiB2YWx1ZSA9PT0gJ29iamVjdCcgJiYgdmFsdWUuX190eXBlID09PSAnUG9pbnRlcicpIHtcbiAgICByZXR1cm4gdmFsdWUub2JqZWN0SWQ7XG4gIH1cbiAgcmV0dXJuIHZhbHVlO1xufTtcblxuLy8gRHVwbGljYXRlIGZyb20gdGhlbiBtb25nbyBhZGFwdGVyLi4uXG5jb25zdCBlbXB0eUNMUFMgPSBPYmplY3QuZnJlZXplKHtcbiAgZmluZDoge30sXG4gIGdldDoge30sXG4gIGNvdW50OiB7fSxcbiAgY3JlYXRlOiB7fSxcbiAgdXBkYXRlOiB7fSxcbiAgZGVsZXRlOiB7fSxcbiAgYWRkRmllbGQ6IHt9LFxuICBwcm90ZWN0ZWRGaWVsZHM6IHt9LFxufSk7XG5cbmNvbnN0IGRlZmF1bHRDTFBTID0gT2JqZWN0LmZyZWV6ZSh7XG4gIGZpbmQ6IHsgJyonOiB0cnVlIH0sXG4gIGdldDogeyAnKic6IHRydWUgfSxcbiAgY291bnQ6IHsgJyonOiB0cnVlIH0sXG4gIGNyZWF0ZTogeyAnKic6IHRydWUgfSxcbiAgdXBkYXRlOiB7ICcqJzogdHJ1ZSB9LFxuICBkZWxldGU6IHsgJyonOiB0cnVlIH0sXG4gIGFkZEZpZWxkOiB7ICcqJzogdHJ1ZSB9LFxuICBwcm90ZWN0ZWRGaWVsZHM6IHsgJyonOiBbXSB9LFxufSk7XG5cbmNvbnN0IHRvUGFyc2VTY2hlbWEgPSBzY2hlbWEgPT4ge1xuICBpZiAoc2NoZW1hLmNsYXNzTmFtZSA9PT0gJ19Vc2VyJykge1xuICAgIGRlbGV0ZSBzY2hlbWEuZmllbGRzLl9oYXNoZWRfcGFzc3dvcmQ7XG4gIH1cbiAgaWYgKHNjaGVtYS5maWVsZHMpIHtcbiAgICBkZWxldGUgc2NoZW1hLmZpZWxkcy5fd3Blcm07XG4gICAgZGVsZXRlIHNjaGVtYS5maWVsZHMuX3JwZXJtO1xuICB9XG4gIGxldCBjbHBzID0gZGVmYXVsdENMUFM7XG4gIGlmIChzY2hlbWEuY2xhc3NMZXZlbFBlcm1pc3Npb25zKSB7XG4gICAgY2xwcyA9IHsgLi4uZW1wdHlDTFBTLCAuLi5zY2hlbWEuY2xhc3NMZXZlbFBlcm1pc3Npb25zIH07XG4gIH1cbiAgbGV0IGluZGV4ZXMgPSB7fTtcbiAgaWYgKHNjaGVtYS5pbmRleGVzKSB7XG4gICAgaW5kZXhlcyA9IHsgLi4uc2NoZW1hLmluZGV4ZXMgfTtcbiAgfVxuICByZXR1cm4ge1xuICAgIGNsYXNzTmFtZTogc2NoZW1hLmNsYXNzTmFtZSxcbiAgICBmaWVsZHM6IHNjaGVtYS5maWVsZHMsXG4gICAgY2xhc3NMZXZlbFBlcm1pc3Npb25zOiBjbHBzLFxuICAgIGluZGV4ZXMsXG4gIH07XG59O1xuXG5jb25zdCB0b1Bvc3RncmVzU2NoZW1hID0gc2NoZW1hID0+IHtcbiAgaWYgKCFzY2hlbWEpIHtcbiAgICByZXR1cm4gc2NoZW1hO1xuICB9XG4gIHNjaGVtYS5maWVsZHMgPSBzY2hlbWEuZmllbGRzIHx8IHt9O1xuICBzY2hlbWEuZmllbGRzLl93cGVybSA9IHsgdHlwZTogJ0FycmF5JywgY29udGVudHM6IHsgdHlwZTogJ1N0cmluZycgfSB9O1xuICBzY2hlbWEuZmllbGRzLl9ycGVybSA9IHsgdHlwZTogJ0FycmF5JywgY29udGVudHM6IHsgdHlwZTogJ1N0cmluZycgfSB9O1xuICBpZiAoc2NoZW1hLmNsYXNzTmFtZSA9PT0gJ19Vc2VyJykge1xuICAgIHNjaGVtYS5maWVsZHMuX2hhc2hlZF9wYXNzd29yZCA9IHsgdHlwZTogJ1N0cmluZycgfTtcbiAgICBzY2hlbWEuZmllbGRzLl9wYXNzd29yZF9oaXN0b3J5ID0geyB0eXBlOiAnQXJyYXknIH07XG4gIH1cbiAgcmV0dXJuIHNjaGVtYTtcbn07XG5cbmNvbnN0IGhhbmRsZURvdEZpZWxkcyA9IG9iamVjdCA9PiB7XG4gIE9iamVjdC5rZXlzKG9iamVjdCkuZm9yRWFjaChmaWVsZE5hbWUgPT4ge1xuICAgIGlmIChmaWVsZE5hbWUuaW5kZXhPZignLicpID4gLTEpIHtcbiAgICAgIGNvbnN0IGNvbXBvbmVudHMgPSBmaWVsZE5hbWUuc3BsaXQoJy4nKTtcbiAgICAgIGNvbnN0IGZpcnN0ID0gY29tcG9uZW50cy5zaGlmdCgpO1xuICAgICAgb2JqZWN0W2ZpcnN0XSA9IG9iamVjdFtmaXJzdF0gfHwge307XG4gICAgICBsZXQgY3VycmVudE9iaiA9IG9iamVjdFtmaXJzdF07XG4gICAgICBsZXQgbmV4dDtcbiAgICAgIGxldCB2YWx1ZSA9IG9iamVjdFtmaWVsZE5hbWVdO1xuICAgICAgaWYgKHZhbHVlICYmIHZhbHVlLl9fb3AgPT09ICdEZWxldGUnKSB7XG4gICAgICAgIHZhbHVlID0gdW5kZWZpbmVkO1xuICAgICAgfVxuICAgICAgLyogZXNsaW50LWRpc2FibGUgbm8tY29uZC1hc3NpZ24gKi9cbiAgICAgIHdoaWxlICgobmV4dCA9IGNvbXBvbmVudHMuc2hpZnQoKSkpIHtcbiAgICAgICAgLyogZXNsaW50LWVuYWJsZSBuby1jb25kLWFzc2lnbiAqL1xuICAgICAgICBjdXJyZW50T2JqW25leHRdID0gY3VycmVudE9ialtuZXh0XSB8fCB7fTtcbiAgICAgICAgaWYgKGNvbXBvbmVudHMubGVuZ3RoID09PSAwKSB7XG4gICAgICAgICAgY3VycmVudE9ialtuZXh0XSA9IHZhbHVlO1xuICAgICAgICB9XG4gICAgICAgIGN1cnJlbnRPYmogPSBjdXJyZW50T2JqW25leHRdO1xuICAgICAgfVxuICAgICAgZGVsZXRlIG9iamVjdFtmaWVsZE5hbWVdO1xuICAgIH1cbiAgfSk7XG4gIHJldHVybiBvYmplY3Q7XG59O1xuXG5jb25zdCB0cmFuc2Zvcm1Eb3RGaWVsZFRvQ29tcG9uZW50cyA9IGZpZWxkTmFtZSA9PiB7XG4gIHJldHVybiBmaWVsZE5hbWUuc3BsaXQoJy4nKS5tYXAoKGNtcHQsIGluZGV4KSA9PiB7XG4gICAgaWYgKGluZGV4ID09PSAwKSB7XG4gICAgICByZXR1cm4gYFwiJHtjbXB0fVwiYDtcbiAgICB9XG4gICAgcmV0dXJuIGAnJHtjbXB0fSdgO1xuICB9KTtcbn07XG5cbmNvbnN0IHRyYW5zZm9ybURvdEZpZWxkID0gZmllbGROYW1lID0+IHtcbiAgaWYgKGZpZWxkTmFtZS5pbmRleE9mKCcuJykgPT09IC0xKSB7XG4gICAgcmV0dXJuIGBcIiR7ZmllbGROYW1lfVwiYDtcbiAgfVxuICBjb25zdCBjb21wb25lbnRzID0gdHJhbnNmb3JtRG90RmllbGRUb0NvbXBvbmVudHMoZmllbGROYW1lKTtcbiAgbGV0IG5hbWUgPSBjb21wb25lbnRzLnNsaWNlKDAsIGNvbXBvbmVudHMubGVuZ3RoIC0gMSkuam9pbignLT4nKTtcbiAgbmFtZSArPSAnLT4+JyArIGNvbXBvbmVudHNbY29tcG9uZW50cy5sZW5ndGggLSAxXTtcbiAgcmV0dXJuIG5hbWU7XG59O1xuXG5jb25zdCB0cmFuc2Zvcm1BZ2dyZWdhdGVGaWVsZCA9IGZpZWxkTmFtZSA9PiB7XG4gIGlmICh0eXBlb2YgZmllbGROYW1lICE9PSAnc3RyaW5nJykge1xuICAgIHJldHVybiBmaWVsZE5hbWU7XG4gIH1cbiAgaWYgKGZpZWxkTmFtZSA9PT0gJyRfY3JlYXRlZF9hdCcpIHtcbiAgICByZXR1cm4gJ2NyZWF0ZWRBdCc7XG4gIH1cbiAgaWYgKGZpZWxkTmFtZSA9PT0gJyRfdXBkYXRlZF9hdCcpIHtcbiAgICByZXR1cm4gJ3VwZGF0ZWRBdCc7XG4gIH1cbiAgcmV0dXJuIGZpZWxkTmFtZS5zdWJzdHIoMSk7XG59O1xuXG5jb25zdCB2YWxpZGF0ZUtleXMgPSBvYmplY3QgPT4ge1xuICBpZiAodHlwZW9mIG9iamVjdCA9PSAnb2JqZWN0Jykge1xuICAgIGZvciAoY29uc3Qga2V5IGluIG9iamVjdCkge1xuICAgICAgaWYgKHR5cGVvZiBvYmplY3Rba2V5XSA9PSAnb2JqZWN0Jykge1xuICAgICAgICB2YWxpZGF0ZUtleXMob2JqZWN0W2tleV0pO1xuICAgICAgfVxuXG4gICAgICBpZiAoa2V5LmluY2x1ZGVzKCckJykgfHwga2V5LmluY2x1ZGVzKCcuJykpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfTkVTVEVEX0tFWSxcbiAgICAgICAgICBcIk5lc3RlZCBrZXlzIHNob3VsZCBub3QgY29udGFpbiB0aGUgJyQnIG9yICcuJyBjaGFyYWN0ZXJzXCJcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cbn07XG5cbi8vIFJldHVybnMgdGhlIGxpc3Qgb2Ygam9pbiB0YWJsZXMgb24gYSBzY2hlbWFcbmNvbnN0IGpvaW5UYWJsZXNGb3JTY2hlbWEgPSBzY2hlbWEgPT4ge1xuICBjb25zdCBsaXN0ID0gW107XG4gIGlmIChzY2hlbWEpIHtcbiAgICBPYmplY3Qua2V5cyhzY2hlbWEuZmllbGRzKS5mb3JFYWNoKGZpZWxkID0+IHtcbiAgICAgIGlmIChzY2hlbWEuZmllbGRzW2ZpZWxkXS50eXBlID09PSAnUmVsYXRpb24nKSB7XG4gICAgICAgIGxpc3QucHVzaChgX0pvaW46JHtmaWVsZH06JHtzY2hlbWEuY2xhc3NOYW1lfWApO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG4gIHJldHVybiBsaXN0O1xufTtcblxuaW50ZXJmYWNlIFdoZXJlQ2xhdXNlIHtcbiAgcGF0dGVybjogc3RyaW5nO1xuICB2YWx1ZXM6IEFycmF5PGFueT47XG4gIHNvcnRzOiBBcnJheTxhbnk+O1xufVxuXG5jb25zdCBidWlsZFdoZXJlQ2xhdXNlID0gKHsgc2NoZW1hLCBxdWVyeSwgaW5kZXgsIGNhc2VJbnNlbnNpdGl2ZSB9KTogV2hlcmVDbGF1c2UgPT4ge1xuICBjb25zdCBwYXR0ZXJucyA9IFtdO1xuICBsZXQgdmFsdWVzID0gW107XG4gIGNvbnN0IHNvcnRzID0gW107XG5cbiAgc2NoZW1hID0gdG9Qb3N0Z3Jlc1NjaGVtYShzY2hlbWEpO1xuICBmb3IgKGNvbnN0IGZpZWxkTmFtZSBpbiBxdWVyeSkge1xuICAgIGNvbnN0IGlzQXJyYXlGaWVsZCA9XG4gICAgICBzY2hlbWEuZmllbGRzICYmIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXSAmJiBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0udHlwZSA9PT0gJ0FycmF5JztcbiAgICBjb25zdCBpbml0aWFsUGF0dGVybnNMZW5ndGggPSBwYXR0ZXJucy5sZW5ndGg7XG4gICAgY29uc3QgZmllbGRWYWx1ZSA9IHF1ZXJ5W2ZpZWxkTmFtZV07XG5cbiAgICAvLyBub3RoaW5nIGluIHRoZSBzY2hlbWEsIGl0J3MgZ29ubmEgYmxvdyB1cFxuICAgIGlmICghc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdKSB7XG4gICAgICAvLyBhcyBpdCB3b24ndCBleGlzdFxuICAgICAgaWYgKGZpZWxkVmFsdWUgJiYgZmllbGRWYWx1ZS4kZXhpc3RzID09PSBmYWxzZSkge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCBhdXRoRGF0YU1hdGNoID0gZmllbGROYW1lLm1hdGNoKC9eX2F1dGhfZGF0YV8oW2EtekEtWjAtOV9dKykkLyk7XG4gICAgaWYgKGF1dGhEYXRhTWF0Y2gpIHtcbiAgICAgIC8vIFRPRE86IEhhbmRsZSBxdWVyeWluZyBieSBfYXV0aF9kYXRhX3Byb3ZpZGVyLCBhdXRoRGF0YSBpcyBzdG9yZWQgaW4gYXV0aERhdGEgZmllbGRcbiAgICAgIGNvbnRpbnVlO1xuICAgIH0gZWxzZSBpZiAoY2FzZUluc2Vuc2l0aXZlICYmIChmaWVsZE5hbWUgPT09ICd1c2VybmFtZScgfHwgZmllbGROYW1lID09PSAnZW1haWwnKSkge1xuICAgICAgcGF0dGVybnMucHVzaChgTE9XRVIoJCR7aW5kZXh9Om5hbWUpID0gTE9XRVIoJCR7aW5kZXggKyAxfSlgKTtcbiAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgZmllbGRWYWx1ZSk7XG4gICAgICBpbmRleCArPSAyO1xuICAgIH0gZWxzZSBpZiAoZmllbGROYW1lLmluZGV4T2YoJy4nKSA+PSAwKSB7XG4gICAgICBsZXQgbmFtZSA9IHRyYW5zZm9ybURvdEZpZWxkKGZpZWxkTmFtZSk7XG4gICAgICBpZiAoZmllbGRWYWx1ZSA9PT0gbnVsbCkge1xuICAgICAgICBwYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06cmF3IElTIE5VTExgKTtcbiAgICAgICAgdmFsdWVzLnB1c2gobmFtZSk7XG4gICAgICAgIGluZGV4ICs9IDE7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgaWYgKGZpZWxkVmFsdWUuJGluKSB7XG4gICAgICAgICAgbmFtZSA9IHRyYW5zZm9ybURvdEZpZWxkVG9Db21wb25lbnRzKGZpZWxkTmFtZSkuam9pbignLT4nKTtcbiAgICAgICAgICBwYXR0ZXJucy5wdXNoKGAoJCR7aW5kZXh9OnJhdyk6Ompzb25iIEA+ICQke2luZGV4ICsgMX06Ompzb25iYCk7XG4gICAgICAgICAgdmFsdWVzLnB1c2gobmFtZSwgSlNPTi5zdHJpbmdpZnkoZmllbGRWYWx1ZS4kaW4pKTtcbiAgICAgICAgICBpbmRleCArPSAyO1xuICAgICAgICB9IGVsc2UgaWYgKGZpZWxkVmFsdWUuJHJlZ2V4KSB7XG4gICAgICAgICAgLy8gSGFuZGxlIGxhdGVyXG4gICAgICAgIH0gZWxzZSBpZiAodHlwZW9mIGZpZWxkVmFsdWUgIT09ICdvYmplY3QnKSB7XG4gICAgICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9OnJhdyA9ICQke2luZGV4ICsgMX06OnRleHRgKTtcbiAgICAgICAgICB2YWx1ZXMucHVzaChuYW1lLCBmaWVsZFZhbHVlKTtcbiAgICAgICAgICBpbmRleCArPSAyO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBlbHNlIGlmIChmaWVsZFZhbHVlID09PSBudWxsIHx8IGZpZWxkVmFsdWUgPT09IHVuZGVmaW5lZCkge1xuICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgSVMgTlVMTGApO1xuICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lKTtcbiAgICAgIGluZGV4ICs9IDE7XG4gICAgICBjb250aW51ZTtcbiAgICB9IGVsc2UgaWYgKHR5cGVvZiBmaWVsZFZhbHVlID09PSAnc3RyaW5nJykge1xuICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgPSAkJHtpbmRleCArIDF9YCk7XG4gICAgICB2YWx1ZXMucHVzaChmaWVsZE5hbWUsIGZpZWxkVmFsdWUpO1xuICAgICAgaW5kZXggKz0gMjtcbiAgICB9IGVsc2UgaWYgKHR5cGVvZiBmaWVsZFZhbHVlID09PSAnYm9vbGVhbicpIHtcbiAgICAgIHBhdHRlcm5zLnB1c2goYCQke2luZGV4fTpuYW1lID0gJCR7aW5kZXggKyAxfWApO1xuICAgICAgLy8gQ2FuJ3QgY2FzdCBib29sZWFuIHRvIGRvdWJsZSBwcmVjaXNpb25cbiAgICAgIGlmIChzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0gJiYgc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdLnR5cGUgPT09ICdOdW1iZXInKSB7XG4gICAgICAgIC8vIFNob3VsZCBhbHdheXMgcmV0dXJuIHplcm8gcmVzdWx0c1xuICAgICAgICBjb25zdCBNQVhfSU5UX1BMVVNfT05FID0gOTIyMzM3MjAzNjg1NDc3NTgwODtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBNQVhfSU5UX1BMVVNfT05FKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgZmllbGRWYWx1ZSk7XG4gICAgICB9XG4gICAgICBpbmRleCArPSAyO1xuICAgIH0gZWxzZSBpZiAodHlwZW9mIGZpZWxkVmFsdWUgPT09ICdudW1iZXInKSB7XG4gICAgICBwYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9ICQke2luZGV4ICsgMX1gKTtcbiAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgZmllbGRWYWx1ZSk7XG4gICAgICBpbmRleCArPSAyO1xuICAgIH0gZWxzZSBpZiAoWyckb3InLCAnJG5vcicsICckYW5kJ10uaW5jbHVkZXMoZmllbGROYW1lKSkge1xuICAgICAgY29uc3QgY2xhdXNlcyA9IFtdO1xuICAgICAgY29uc3QgY2xhdXNlVmFsdWVzID0gW107XG4gICAgICBmaWVsZFZhbHVlLmZvckVhY2goc3ViUXVlcnkgPT4ge1xuICAgICAgICBjb25zdCBjbGF1c2UgPSBidWlsZFdoZXJlQ2xhdXNlKHtcbiAgICAgICAgICBzY2hlbWEsXG4gICAgICAgICAgcXVlcnk6IHN1YlF1ZXJ5LFxuICAgICAgICAgIGluZGV4LFxuICAgICAgICAgIGNhc2VJbnNlbnNpdGl2ZSxcbiAgICAgICAgfSk7XG4gICAgICAgIGlmIChjbGF1c2UucGF0dGVybi5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgY2xhdXNlcy5wdXNoKGNsYXVzZS5wYXR0ZXJuKTtcbiAgICAgICAgICBjbGF1c2VWYWx1ZXMucHVzaCguLi5jbGF1c2UudmFsdWVzKTtcbiAgICAgICAgICBpbmRleCArPSBjbGF1c2UudmFsdWVzLmxlbmd0aDtcbiAgICAgICAgfVxuICAgICAgfSk7XG5cbiAgICAgIGNvbnN0IG9yT3JBbmQgPSBmaWVsZE5hbWUgPT09ICckYW5kJyA/ICcgQU5EICcgOiAnIE9SICc7XG4gICAgICBjb25zdCBub3QgPSBmaWVsZE5hbWUgPT09ICckbm9yJyA/ICcgTk9UICcgOiAnJztcblxuICAgICAgcGF0dGVybnMucHVzaChgJHtub3R9KCR7Y2xhdXNlcy5qb2luKG9yT3JBbmQpfSlgKTtcbiAgICAgIHZhbHVlcy5wdXNoKC4uLmNsYXVzZVZhbHVlcyk7XG4gICAgfVxuXG4gICAgaWYgKGZpZWxkVmFsdWUuJG5lICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIGlmIChpc0FycmF5RmllbGQpIHtcbiAgICAgICAgZmllbGRWYWx1ZS4kbmUgPSBKU09OLnN0cmluZ2lmeShbZmllbGRWYWx1ZS4kbmVdKTtcbiAgICAgICAgcGF0dGVybnMucHVzaChgTk9UIGFycmF5X2NvbnRhaW5zKCQke2luZGV4fTpuYW1lLCAkJHtpbmRleCArIDF9KWApO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgaWYgKGZpZWxkVmFsdWUuJG5lID09PSBudWxsKSB7XG4gICAgICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgSVMgTk9UIE5VTExgKTtcbiAgICAgICAgICB2YWx1ZXMucHVzaChmaWVsZE5hbWUpO1xuICAgICAgICAgIGluZGV4ICs9IDE7XG4gICAgICAgICAgY29udGludWU7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgLy8gaWYgbm90IG51bGwsIHdlIG5lZWQgdG8gbWFudWFsbHkgZXhjbHVkZSBudWxsXG4gICAgICAgICAgaWYgKGZpZWxkVmFsdWUuJG5lLl9fdHlwZSA9PT0gJ0dlb1BvaW50Jykge1xuICAgICAgICAgICAgcGF0dGVybnMucHVzaChcbiAgICAgICAgICAgICAgYCgkJHtpbmRleH06bmFtZSA8PiBQT0lOVCgkJHtpbmRleCArIDF9LCAkJHtpbmRleCArIDJ9KSBPUiAkJHtpbmRleH06bmFtZSBJUyBOVUxMKWBcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGlmIChmaWVsZE5hbWUuaW5kZXhPZignLicpID49IDApIHtcbiAgICAgICAgICAgICAgY29uc3QgY29uc3RyYWludEZpZWxkTmFtZSA9IHRyYW5zZm9ybURvdEZpZWxkKGZpZWxkTmFtZSk7XG4gICAgICAgICAgICAgIHBhdHRlcm5zLnB1c2goXG4gICAgICAgICAgICAgICAgYCgke2NvbnN0cmFpbnRGaWVsZE5hbWV9IDw+ICQke2luZGV4fSBPUiAke2NvbnN0cmFpbnRGaWVsZE5hbWV9IElTIE5VTEwpYFxuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgcGF0dGVybnMucHVzaChgKCQke2luZGV4fTpuYW1lIDw+ICQke2luZGV4ICsgMX0gT1IgJCR7aW5kZXh9Om5hbWUgSVMgTlVMTClgKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGlmIChmaWVsZFZhbHVlLiRuZS5fX3R5cGUgPT09ICdHZW9Qb2ludCcpIHtcbiAgICAgICAgY29uc3QgcG9pbnQgPSBmaWVsZFZhbHVlLiRuZTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBwb2ludC5sb25naXR1ZGUsIHBvaW50LmxhdGl0dWRlKTtcbiAgICAgICAgaW5kZXggKz0gMztcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIC8vIFRPRE86IHN1cHBvcnQgYXJyYXlzXG4gICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgZmllbGRWYWx1ZS4kbmUpO1xuICAgICAgICBpbmRleCArPSAyO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAoZmllbGRWYWx1ZS4kZXEgIT09IHVuZGVmaW5lZCkge1xuICAgICAgaWYgKGZpZWxkVmFsdWUuJGVxID09PSBudWxsKSB7XG4gICAgICAgIHBhdHRlcm5zLnB1c2goYCQke2luZGV4fTpuYW1lIElTIE5VTExgKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lKTtcbiAgICAgICAgaW5kZXggKz0gMTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGlmIChmaWVsZE5hbWUuaW5kZXhPZignLicpID49IDApIHtcbiAgICAgICAgICB2YWx1ZXMucHVzaChmaWVsZFZhbHVlLiRlcSk7XG4gICAgICAgICAgcGF0dGVybnMucHVzaChgJHt0cmFuc2Zvcm1Eb3RGaWVsZChmaWVsZE5hbWUpfSA9ICQke2luZGV4Kyt9YCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBmaWVsZFZhbHVlLiRlcSk7XG4gICAgICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgPSAkJHtpbmRleCArIDF9YCk7XG4gICAgICAgICAgaW5kZXggKz0gMjtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICBjb25zdCBpc0luT3JOaW4gPSBBcnJheS5pc0FycmF5KGZpZWxkVmFsdWUuJGluKSB8fCBBcnJheS5pc0FycmF5KGZpZWxkVmFsdWUuJG5pbik7XG4gICAgaWYgKFxuICAgICAgQXJyYXkuaXNBcnJheShmaWVsZFZhbHVlLiRpbikgJiZcbiAgICAgIGlzQXJyYXlGaWVsZCAmJlxuICAgICAgc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdLmNvbnRlbnRzICYmXG4gICAgICBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0uY29udGVudHMudHlwZSA9PT0gJ1N0cmluZydcbiAgICApIHtcbiAgICAgIGNvbnN0IGluUGF0dGVybnMgPSBbXTtcbiAgICAgIGxldCBhbGxvd051bGwgPSBmYWxzZTtcbiAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSk7XG4gICAgICBmaWVsZFZhbHVlLiRpbi5mb3JFYWNoKChsaXN0RWxlbSwgbGlzdEluZGV4KSA9PiB7XG4gICAgICAgIGlmIChsaXN0RWxlbSA9PT0gbnVsbCkge1xuICAgICAgICAgIGFsbG93TnVsbCA9IHRydWU7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdmFsdWVzLnB1c2gobGlzdEVsZW0pO1xuICAgICAgICAgIGluUGF0dGVybnMucHVzaChgJCR7aW5kZXggKyAxICsgbGlzdEluZGV4IC0gKGFsbG93TnVsbCA/IDEgOiAwKX1gKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgICBpZiAoYWxsb3dOdWxsKSB7XG4gICAgICAgIHBhdHRlcm5zLnB1c2goYCgkJHtpbmRleH06bmFtZSBJUyBOVUxMIE9SICQke2luZGV4fTpuYW1lICYmIEFSUkFZWyR7aW5QYXR0ZXJucy5qb2luKCl9XSlgKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHBhdHRlcm5zLnB1c2goYCQke2luZGV4fTpuYW1lICYmIEFSUkFZWyR7aW5QYXR0ZXJucy5qb2luKCl9XWApO1xuICAgICAgfVxuICAgICAgaW5kZXggPSBpbmRleCArIDEgKyBpblBhdHRlcm5zLmxlbmd0aDtcbiAgICB9IGVsc2UgaWYgKGlzSW5Pck5pbikge1xuICAgICAgdmFyIGNyZWF0ZUNvbnN0cmFpbnQgPSAoYmFzZUFycmF5LCBub3RJbikgPT4ge1xuICAgICAgICBjb25zdCBub3QgPSBub3RJbiA/ICcgTk9UICcgOiAnJztcbiAgICAgICAgaWYgKGJhc2VBcnJheS5sZW5ndGggPiAwKSB7XG4gICAgICAgICAgaWYgKGlzQXJyYXlGaWVsZCkge1xuICAgICAgICAgICAgcGF0dGVybnMucHVzaChgJHtub3R9IGFycmF5X2NvbnRhaW5zKCQke2luZGV4fTpuYW1lLCAkJHtpbmRleCArIDF9KWApO1xuICAgICAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBKU09OLnN0cmluZ2lmeShiYXNlQXJyYXkpKTtcbiAgICAgICAgICAgIGluZGV4ICs9IDI7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIC8vIEhhbmRsZSBOZXN0ZWQgRG90IE5vdGF0aW9uIEFib3ZlXG4gICAgICAgICAgICBpZiAoZmllbGROYW1lLmluZGV4T2YoJy4nKSA+PSAwKSB7XG4gICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IGluUGF0dGVybnMgPSBbXTtcbiAgICAgICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSk7XG4gICAgICAgICAgICBiYXNlQXJyYXkuZm9yRWFjaCgobGlzdEVsZW0sIGxpc3RJbmRleCkgPT4ge1xuICAgICAgICAgICAgICBpZiAobGlzdEVsZW0gIT0gbnVsbCkge1xuICAgICAgICAgICAgICAgIHZhbHVlcy5wdXNoKGxpc3RFbGVtKTtcbiAgICAgICAgICAgICAgICBpblBhdHRlcm5zLnB1c2goYCQke2luZGV4ICsgMSArIGxpc3RJbmRleH1gKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBwYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSAke25vdH0gSU4gKCR7aW5QYXR0ZXJucy5qb2luKCl9KWApO1xuICAgICAgICAgICAgaW5kZXggPSBpbmRleCArIDEgKyBpblBhdHRlcm5zLmxlbmd0aDtcbiAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSBpZiAoIW5vdEluKSB7XG4gICAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lKTtcbiAgICAgICAgICBwYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSBJUyBOVUxMYCk7XG4gICAgICAgICAgaW5kZXggPSBpbmRleCArIDE7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgLy8gSGFuZGxlIGVtcHR5IGFycmF5XG4gICAgICAgICAgaWYgKG5vdEluKSB7XG4gICAgICAgICAgICBwYXR0ZXJucy5wdXNoKCcxID0gMScpOyAvLyBSZXR1cm4gYWxsIHZhbHVlc1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBwYXR0ZXJucy5wdXNoKCcxID0gMicpOyAvLyBSZXR1cm4gbm8gdmFsdWVzXG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9O1xuICAgICAgaWYgKGZpZWxkVmFsdWUuJGluKSB7XG4gICAgICAgIGNyZWF0ZUNvbnN0cmFpbnQoXG4gICAgICAgICAgXy5mbGF0TWFwKGZpZWxkVmFsdWUuJGluLCBlbHQgPT4gZWx0KSxcbiAgICAgICAgICBmYWxzZVxuICAgICAgICApO1xuICAgICAgfVxuICAgICAgaWYgKGZpZWxkVmFsdWUuJG5pbikge1xuICAgICAgICBjcmVhdGVDb25zdHJhaW50KFxuICAgICAgICAgIF8uZmxhdE1hcChmaWVsZFZhbHVlLiRuaW4sIGVsdCA9PiBlbHQpLFxuICAgICAgICAgIHRydWVcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9IGVsc2UgaWYgKHR5cGVvZiBmaWVsZFZhbHVlLiRpbiAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sICdiYWQgJGluIHZhbHVlJyk7XG4gICAgfSBlbHNlIGlmICh0eXBlb2YgZmllbGRWYWx1ZS4kbmluICE9PSAndW5kZWZpbmVkJykge1xuICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgJ2JhZCAkbmluIHZhbHVlJyk7XG4gICAgfVxuXG4gICAgaWYgKEFycmF5LmlzQXJyYXkoZmllbGRWYWx1ZS4kYWxsKSAmJiBpc0FycmF5RmllbGQpIHtcbiAgICAgIGlmIChpc0FueVZhbHVlUmVnZXhTdGFydHNXaXRoKGZpZWxkVmFsdWUuJGFsbCkpIHtcbiAgICAgICAgaWYgKCFpc0FsbFZhbHVlc1JlZ2V4T3JOb25lKGZpZWxkVmFsdWUuJGFsbCkpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sXG4gICAgICAgICAgICAnQWxsICRhbGwgdmFsdWVzIG11c3QgYmUgb2YgcmVnZXggdHlwZSBvciBub25lOiAnICsgZmllbGRWYWx1ZS4kYWxsXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZvciAobGV0IGkgPSAwOyBpIDwgZmllbGRWYWx1ZS4kYWxsLmxlbmd0aDsgaSArPSAxKSB7XG4gICAgICAgICAgY29uc3QgdmFsdWUgPSBwcm9jZXNzUmVnZXhQYXR0ZXJuKGZpZWxkVmFsdWUuJGFsbFtpXS4kcmVnZXgpO1xuICAgICAgICAgIGZpZWxkVmFsdWUuJGFsbFtpXSA9IHZhbHVlLnN1YnN0cmluZygxKSArICclJztcbiAgICAgICAgfVxuICAgICAgICBwYXR0ZXJucy5wdXNoKGBhcnJheV9jb250YWluc19hbGxfcmVnZXgoJCR7aW5kZXh9Om5hbWUsICQke2luZGV4ICsgMX06Ompzb25iKWApO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcGF0dGVybnMucHVzaChgYXJyYXlfY29udGFpbnNfYWxsKCQke2luZGV4fTpuYW1lLCAkJHtpbmRleCArIDF9Ojpqc29uYilgKTtcbiAgICAgIH1cbiAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgSlNPTi5zdHJpbmdpZnkoZmllbGRWYWx1ZS4kYWxsKSk7XG4gICAgICBpbmRleCArPSAyO1xuICAgIH0gZWxzZSBpZiAoQXJyYXkuaXNBcnJheShmaWVsZFZhbHVlLiRhbGwpKSB7XG4gICAgICBpZiAoZmllbGRWYWx1ZS4kYWxsLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICBwYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9ICQke2luZGV4ICsgMX1gKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBmaWVsZFZhbHVlLiRhbGxbMF0ub2JqZWN0SWQpO1xuICAgICAgICBpbmRleCArPSAyO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmICh0eXBlb2YgZmllbGRWYWx1ZS4kZXhpc3RzICE9PSAndW5kZWZpbmVkJykge1xuICAgICAgaWYgKGZpZWxkVmFsdWUuJGV4aXN0cykge1xuICAgICAgICBwYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSBJUyBOT1QgTlVMTGApO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgSVMgTlVMTGApO1xuICAgICAgfVxuICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lKTtcbiAgICAgIGluZGV4ICs9IDE7XG4gICAgfVxuXG4gICAgaWYgKGZpZWxkVmFsdWUuJGNvbnRhaW5lZEJ5KSB7XG4gICAgICBjb25zdCBhcnIgPSBmaWVsZFZhbHVlLiRjb250YWluZWRCeTtcbiAgICAgIGlmICghKGFyciBpbnN0YW5jZW9mIEFycmF5KSkge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLCBgYmFkICRjb250YWluZWRCeTogc2hvdWxkIGJlIGFuIGFycmF5YCk7XG4gICAgICB9XG5cbiAgICAgIHBhdHRlcm5zLnB1c2goYCQke2luZGV4fTpuYW1lIDxAICQke2luZGV4ICsgMX06Ompzb25iYCk7XG4gICAgICB2YWx1ZXMucHVzaChmaWVsZE5hbWUsIEpTT04uc3RyaW5naWZ5KGFycikpO1xuICAgICAgaW5kZXggKz0gMjtcbiAgICB9XG5cbiAgICBpZiAoZmllbGRWYWx1ZS4kdGV4dCkge1xuICAgICAgY29uc3Qgc2VhcmNoID0gZmllbGRWYWx1ZS4kdGV4dC4kc2VhcmNoO1xuICAgICAgbGV0IGxhbmd1YWdlID0gJ2VuZ2xpc2gnO1xuICAgICAgaWYgKHR5cGVvZiBzZWFyY2ggIT09ICdvYmplY3QnKSB7XG4gICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sIGBiYWQgJHRleHQ6ICRzZWFyY2gsIHNob3VsZCBiZSBvYmplY3RgKTtcbiAgICAgIH1cbiAgICAgIGlmICghc2VhcmNoLiR0ZXJtIHx8IHR5cGVvZiBzZWFyY2guJHRlcm0gIT09ICdzdHJpbmcnKSB7XG4gICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sIGBiYWQgJHRleHQ6ICR0ZXJtLCBzaG91bGQgYmUgc3RyaW5nYCk7XG4gICAgICB9XG4gICAgICBpZiAoc2VhcmNoLiRsYW5ndWFnZSAmJiB0eXBlb2Ygc2VhcmNoLiRsYW5ndWFnZSAhPT0gJ3N0cmluZycpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgYGJhZCAkdGV4dDogJGxhbmd1YWdlLCBzaG91bGQgYmUgc3RyaW5nYCk7XG4gICAgICB9IGVsc2UgaWYgKHNlYXJjaC4kbGFuZ3VhZ2UpIHtcbiAgICAgICAgbGFuZ3VhZ2UgPSBzZWFyY2guJGxhbmd1YWdlO1xuICAgICAgfVxuICAgICAgaWYgKHNlYXJjaC4kY2FzZVNlbnNpdGl2ZSAmJiB0eXBlb2Ygc2VhcmNoLiRjYXNlU2Vuc2l0aXZlICE9PSAnYm9vbGVhbicpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgICBgYmFkICR0ZXh0OiAkY2FzZVNlbnNpdGl2ZSwgc2hvdWxkIGJlIGJvb2xlYW5gXG4gICAgICAgICk7XG4gICAgICB9IGVsc2UgaWYgKHNlYXJjaC4kY2FzZVNlbnNpdGl2ZSkge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgIGBiYWQgJHRleHQ6ICRjYXNlU2Vuc2l0aXZlIG5vdCBzdXBwb3J0ZWQsIHBsZWFzZSB1c2UgJHJlZ2V4IG9yIGNyZWF0ZSBhIHNlcGFyYXRlIGxvd2VyIGNhc2UgY29sdW1uLmBcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIGlmIChzZWFyY2guJGRpYWNyaXRpY1NlbnNpdGl2ZSAmJiB0eXBlb2Ygc2VhcmNoLiRkaWFjcml0aWNTZW5zaXRpdmUgIT09ICdib29sZWFuJykge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgIGBiYWQgJHRleHQ6ICRkaWFjcml0aWNTZW5zaXRpdmUsIHNob3VsZCBiZSBib29sZWFuYFxuICAgICAgICApO1xuICAgICAgfSBlbHNlIGlmIChzZWFyY2guJGRpYWNyaXRpY1NlbnNpdGl2ZSA9PT0gZmFsc2UpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgICBgYmFkICR0ZXh0OiAkZGlhY3JpdGljU2Vuc2l0aXZlIC0gZmFsc2Ugbm90IHN1cHBvcnRlZCwgaW5zdGFsbCBQb3N0Z3JlcyBVbmFjY2VudCBFeHRlbnNpb25gXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgICBwYXR0ZXJucy5wdXNoKFxuICAgICAgICBgdG9fdHN2ZWN0b3IoJCR7aW5kZXh9LCAkJHtpbmRleCArIDF9Om5hbWUpIEBAIHRvX3RzcXVlcnkoJCR7aW5kZXggKyAyfSwgJCR7aW5kZXggKyAzfSlgXG4gICAgICApO1xuICAgICAgdmFsdWVzLnB1c2gobGFuZ3VhZ2UsIGZpZWxkTmFtZSwgbGFuZ3VhZ2UsIHNlYXJjaC4kdGVybSk7XG4gICAgICBpbmRleCArPSA0O1xuICAgIH1cblxuICAgIGlmIChmaWVsZFZhbHVlLiRuZWFyU3BoZXJlKSB7XG4gICAgICBjb25zdCBwb2ludCA9IGZpZWxkVmFsdWUuJG5lYXJTcGhlcmU7XG4gICAgICBjb25zdCBkaXN0YW5jZSA9IGZpZWxkVmFsdWUuJG1heERpc3RhbmNlO1xuICAgICAgY29uc3QgZGlzdGFuY2VJbktNID0gZGlzdGFuY2UgKiA2MzcxICogMTAwMDtcbiAgICAgIHBhdHRlcm5zLnB1c2goXG4gICAgICAgIGBTVF9EaXN0YW5jZVNwaGVyZSgkJHtpbmRleH06bmFtZTo6Z2VvbWV0cnksIFBPSU5UKCQke2luZGV4ICsgMX0sICQke1xuICAgICAgICAgIGluZGV4ICsgMlxuICAgICAgICB9KTo6Z2VvbWV0cnkpIDw9ICQke2luZGV4ICsgM31gXG4gICAgICApO1xuICAgICAgc29ydHMucHVzaChcbiAgICAgICAgYFNUX0Rpc3RhbmNlU3BoZXJlKCQke2luZGV4fTpuYW1lOjpnZW9tZXRyeSwgUE9JTlQoJCR7aW5kZXggKyAxfSwgJCR7XG4gICAgICAgICAgaW5kZXggKyAyXG4gICAgICAgIH0pOjpnZW9tZXRyeSkgQVNDYFxuICAgICAgKTtcbiAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgcG9pbnQubG9uZ2l0dWRlLCBwb2ludC5sYXRpdHVkZSwgZGlzdGFuY2VJbktNKTtcbiAgICAgIGluZGV4ICs9IDQ7XG4gICAgfVxuXG4gICAgaWYgKGZpZWxkVmFsdWUuJHdpdGhpbiAmJiBmaWVsZFZhbHVlLiR3aXRoaW4uJGJveCkge1xuICAgICAgY29uc3QgYm94ID0gZmllbGRWYWx1ZS4kd2l0aGluLiRib3g7XG4gICAgICBjb25zdCBsZWZ0ID0gYm94WzBdLmxvbmdpdHVkZTtcbiAgICAgIGNvbnN0IGJvdHRvbSA9IGJveFswXS5sYXRpdHVkZTtcbiAgICAgIGNvbnN0IHJpZ2h0ID0gYm94WzFdLmxvbmdpdHVkZTtcbiAgICAgIGNvbnN0IHRvcCA9IGJveFsxXS5sYXRpdHVkZTtcblxuICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWU6OnBvaW50IDxAICQke2luZGV4ICsgMX06OmJveGApO1xuICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBgKCgke2xlZnR9LCAke2JvdHRvbX0pLCAoJHtyaWdodH0sICR7dG9wfSkpYCk7XG4gICAgICBpbmRleCArPSAyO1xuICAgIH1cblxuICAgIGlmIChmaWVsZFZhbHVlLiRnZW9XaXRoaW4gJiYgZmllbGRWYWx1ZS4kZ2VvV2l0aGluLiRjZW50ZXJTcGhlcmUpIHtcbiAgICAgIGNvbnN0IGNlbnRlclNwaGVyZSA9IGZpZWxkVmFsdWUuJGdlb1dpdGhpbi4kY2VudGVyU3BoZXJlO1xuICAgICAgaWYgKCEoY2VudGVyU3BoZXJlIGluc3RhbmNlb2YgQXJyYXkpIHx8IGNlbnRlclNwaGVyZS5sZW5ndGggPCAyKSB7XG4gICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sXG4gICAgICAgICAgJ2JhZCAkZ2VvV2l0aGluIHZhbHVlOyAkY2VudGVyU3BoZXJlIHNob3VsZCBiZSBhbiBhcnJheSBvZiBQYXJzZS5HZW9Qb2ludCBhbmQgZGlzdGFuY2UnXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgICAvLyBHZXQgcG9pbnQsIGNvbnZlcnQgdG8gZ2VvIHBvaW50IGlmIG5lY2Vzc2FyeSBhbmQgdmFsaWRhdGVcbiAgICAgIGxldCBwb2ludCA9IGNlbnRlclNwaGVyZVswXTtcbiAgICAgIGlmIChwb2ludCBpbnN0YW5jZW9mIEFycmF5ICYmIHBvaW50Lmxlbmd0aCA9PT0gMikge1xuICAgICAgICBwb2ludCA9IG5ldyBQYXJzZS5HZW9Qb2ludChwb2ludFsxXSwgcG9pbnRbMF0pO1xuICAgICAgfSBlbHNlIGlmICghR2VvUG9pbnRDb2Rlci5pc1ZhbGlkSlNPTihwb2ludCkpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfSlNPTixcbiAgICAgICAgICAnYmFkICRnZW9XaXRoaW4gdmFsdWU7ICRjZW50ZXJTcGhlcmUgZ2VvIHBvaW50IGludmFsaWQnXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgICBQYXJzZS5HZW9Qb2ludC5fdmFsaWRhdGUocG9pbnQubGF0aXR1ZGUsIHBvaW50LmxvbmdpdHVkZSk7XG4gICAgICAvLyBHZXQgZGlzdGFuY2UgYW5kIHZhbGlkYXRlXG4gICAgICBjb25zdCBkaXN0YW5jZSA9IGNlbnRlclNwaGVyZVsxXTtcbiAgICAgIGlmIChpc05hTihkaXN0YW5jZSkgfHwgZGlzdGFuY2UgPCAwKSB7XG4gICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX0pTT04sXG4gICAgICAgICAgJ2JhZCAkZ2VvV2l0aGluIHZhbHVlOyAkY2VudGVyU3BoZXJlIGRpc3RhbmNlIGludmFsaWQnXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgICBjb25zdCBkaXN0YW5jZUluS00gPSBkaXN0YW5jZSAqIDYzNzEgKiAxMDAwO1xuICAgICAgcGF0dGVybnMucHVzaChcbiAgICAgICAgYFNUX0Rpc3RhbmNlU3BoZXJlKCQke2luZGV4fTpuYW1lOjpnZW9tZXRyeSwgUE9JTlQoJCR7aW5kZXggKyAxfSwgJCR7XG4gICAgICAgICAgaW5kZXggKyAyXG4gICAgICAgIH0pOjpnZW9tZXRyeSkgPD0gJCR7aW5kZXggKyAzfWBcbiAgICAgICk7XG4gICAgICB2YWx1ZXMucHVzaChmaWVsZE5hbWUsIHBvaW50LmxvbmdpdHVkZSwgcG9pbnQubGF0aXR1ZGUsIGRpc3RhbmNlSW5LTSk7XG4gICAgICBpbmRleCArPSA0O1xuICAgIH1cblxuICAgIGlmIChmaWVsZFZhbHVlLiRnZW9XaXRoaW4gJiYgZmllbGRWYWx1ZS4kZ2VvV2l0aGluLiRwb2x5Z29uKSB7XG4gICAgICBjb25zdCBwb2x5Z29uID0gZmllbGRWYWx1ZS4kZ2VvV2l0aGluLiRwb2x5Z29uO1xuICAgICAgbGV0IHBvaW50cztcbiAgICAgIGlmICh0eXBlb2YgcG9seWdvbiA9PT0gJ29iamVjdCcgJiYgcG9seWdvbi5fX3R5cGUgPT09ICdQb2x5Z29uJykge1xuICAgICAgICBpZiAoIXBvbHlnb24uY29vcmRpbmF0ZXMgfHwgcG9seWdvbi5jb29yZGluYXRlcy5sZW5ndGggPCAzKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgJ2JhZCAkZ2VvV2l0aGluIHZhbHVlOyBQb2x5Z29uLmNvb3JkaW5hdGVzIHNob3VsZCBjb250YWluIGF0IGxlYXN0IDMgbG9uL2xhdCBwYWlycydcbiAgICAgICAgICApO1xuICAgICAgICB9XG4gICAgICAgIHBvaW50cyA9IHBvbHlnb24uY29vcmRpbmF0ZXM7XG4gICAgICB9IGVsc2UgaWYgKHBvbHlnb24gaW5zdGFuY2VvZiBBcnJheSkge1xuICAgICAgICBpZiAocG9seWdvbi5sZW5ndGggPCAzKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICAgJ2JhZCAkZ2VvV2l0aGluIHZhbHVlOyAkcG9seWdvbiBzaG91bGQgY29udGFpbiBhdCBsZWFzdCAzIEdlb1BvaW50cydcbiAgICAgICAgICApO1xuICAgICAgICB9XG4gICAgICAgIHBvaW50cyA9IHBvbHlnb247XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgIFwiYmFkICRnZW9XaXRoaW4gdmFsdWU7ICRwb2x5Z29uIHNob3VsZCBiZSBQb2x5Z29uIG9iamVjdCBvciBBcnJheSBvZiBQYXJzZS5HZW9Qb2ludCdzXCJcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIHBvaW50cyA9IHBvaW50c1xuICAgICAgICAubWFwKHBvaW50ID0+IHtcbiAgICAgICAgICBpZiAocG9pbnQgaW5zdGFuY2VvZiBBcnJheSAmJiBwb2ludC5sZW5ndGggPT09IDIpIHtcbiAgICAgICAgICAgIFBhcnNlLkdlb1BvaW50Ll92YWxpZGF0ZShwb2ludFsxXSwgcG9pbnRbMF0pO1xuICAgICAgICAgICAgcmV0dXJuIGAoJHtwb2ludFswXX0sICR7cG9pbnRbMV19KWA7XG4gICAgICAgICAgfVxuICAgICAgICAgIGlmICh0eXBlb2YgcG9pbnQgIT09ICdvYmplY3QnIHx8IHBvaW50Ll9fdHlwZSAhPT0gJ0dlb1BvaW50Jykge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLklOVkFMSURfSlNPTiwgJ2JhZCAkZ2VvV2l0aGluIHZhbHVlJyk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIFBhcnNlLkdlb1BvaW50Ll92YWxpZGF0ZShwb2ludC5sYXRpdHVkZSwgcG9pbnQubG9uZ2l0dWRlKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgcmV0dXJuIGAoJHtwb2ludC5sb25naXR1ZGV9LCAke3BvaW50LmxhdGl0dWRlfSlgO1xuICAgICAgICB9KVxuICAgICAgICAuam9pbignLCAnKTtcblxuICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWU6OnBvaW50IDxAICQke2luZGV4ICsgMX06OnBvbHlnb25gKTtcbiAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgYCgke3BvaW50c30pYCk7XG4gICAgICBpbmRleCArPSAyO1xuICAgIH1cbiAgICBpZiAoZmllbGRWYWx1ZS4kZ2VvSW50ZXJzZWN0cyAmJiBmaWVsZFZhbHVlLiRnZW9JbnRlcnNlY3RzLiRwb2ludCkge1xuICAgICAgY29uc3QgcG9pbnQgPSBmaWVsZFZhbHVlLiRnZW9JbnRlcnNlY3RzLiRwb2ludDtcbiAgICAgIGlmICh0eXBlb2YgcG9pbnQgIT09ICdvYmplY3QnIHx8IHBvaW50Ll9fdHlwZSAhPT0gJ0dlb1BvaW50Jykge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLFxuICAgICAgICAgICdiYWQgJGdlb0ludGVyc2VjdCB2YWx1ZTsgJHBvaW50IHNob3VsZCBiZSBHZW9Qb2ludCdcbiAgICAgICAgKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIFBhcnNlLkdlb1BvaW50Ll92YWxpZGF0ZShwb2ludC5sYXRpdHVkZSwgcG9pbnQubG9uZ2l0dWRlKTtcbiAgICAgIH1cbiAgICAgIHBhdHRlcm5zLnB1c2goYCQke2luZGV4fTpuYW1lOjpwb2x5Z29uIEA+ICQke2luZGV4ICsgMX06OnBvaW50YCk7XG4gICAgICB2YWx1ZXMucHVzaChmaWVsZE5hbWUsIGAoJHtwb2ludC5sb25naXR1ZGV9LCAke3BvaW50LmxhdGl0dWRlfSlgKTtcbiAgICAgIGluZGV4ICs9IDI7XG4gICAgfVxuXG4gICAgaWYgKGZpZWxkVmFsdWUuJHJlZ2V4KSB7XG4gICAgICBsZXQgcmVnZXggPSBmaWVsZFZhbHVlLiRyZWdleDtcbiAgICAgIGxldCBvcGVyYXRvciA9ICd+JztcbiAgICAgIGNvbnN0IG9wdHMgPSBmaWVsZFZhbHVlLiRvcHRpb25zO1xuICAgICAgaWYgKG9wdHMpIHtcbiAgICAgICAgaWYgKG9wdHMuaW5kZXhPZignaScpID49IDApIHtcbiAgICAgICAgICBvcGVyYXRvciA9ICd+Kic7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKG9wdHMuaW5kZXhPZigneCcpID49IDApIHtcbiAgICAgICAgICByZWdleCA9IHJlbW92ZVdoaXRlU3BhY2UocmVnZXgpO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IG5hbWUgPSB0cmFuc2Zvcm1Eb3RGaWVsZChmaWVsZE5hbWUpO1xuICAgICAgcmVnZXggPSBwcm9jZXNzUmVnZXhQYXR0ZXJuKHJlZ2V4KTtcblxuICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9OnJhdyAke29wZXJhdG9yfSAnJCR7aW5kZXggKyAxfTpyYXcnYCk7XG4gICAgICB2YWx1ZXMucHVzaChuYW1lLCByZWdleCk7XG4gICAgICBpbmRleCArPSAyO1xuICAgIH1cblxuICAgIGlmIChmaWVsZFZhbHVlLl9fdHlwZSA9PT0gJ1BvaW50ZXInKSB7XG4gICAgICBpZiAoaXNBcnJheUZpZWxkKSB7XG4gICAgICAgIHBhdHRlcm5zLnB1c2goYGFycmF5X2NvbnRhaW5zKCQke2luZGV4fTpuYW1lLCAkJHtpbmRleCArIDF9KWApO1xuICAgICAgICB2YWx1ZXMucHVzaChmaWVsZE5hbWUsIEpTT04uc3RyaW5naWZ5KFtmaWVsZFZhbHVlXSkpO1xuICAgICAgICBpbmRleCArPSAyO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgPSAkJHtpbmRleCArIDF9YCk7XG4gICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgZmllbGRWYWx1ZS5vYmplY3RJZCk7XG4gICAgICAgIGluZGV4ICs9IDI7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKGZpZWxkVmFsdWUuX190eXBlID09PSAnRGF0ZScpIHtcbiAgICAgIHBhdHRlcm5zLnB1c2goYCQke2luZGV4fTpuYW1lID0gJCR7aW5kZXggKyAxfWApO1xuICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBmaWVsZFZhbHVlLmlzbyk7XG4gICAgICBpbmRleCArPSAyO1xuICAgIH1cblxuICAgIGlmIChmaWVsZFZhbHVlLl9fdHlwZSA9PT0gJ0dlb1BvaW50Jykge1xuICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgfj0gUE9JTlQoJCR7aW5kZXggKyAxfSwgJCR7aW5kZXggKyAyfSlgKTtcbiAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgZmllbGRWYWx1ZS5sb25naXR1ZGUsIGZpZWxkVmFsdWUubGF0aXR1ZGUpO1xuICAgICAgaW5kZXggKz0gMztcbiAgICB9XG5cbiAgICBpZiAoZmllbGRWYWx1ZS5fX3R5cGUgPT09ICdQb2x5Z29uJykge1xuICAgICAgY29uc3QgdmFsdWUgPSBjb252ZXJ0UG9seWdvblRvU1FMKGZpZWxkVmFsdWUuY29vcmRpbmF0ZXMpO1xuICAgICAgcGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgfj0gJCR7aW5kZXggKyAxfTo6cG9seWdvbmApO1xuICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCB2YWx1ZSk7XG4gICAgICBpbmRleCArPSAyO1xuICAgIH1cblxuICAgIE9iamVjdC5rZXlzKFBhcnNlVG9Qb3NncmVzQ29tcGFyYXRvcikuZm9yRWFjaChjbXAgPT4ge1xuICAgICAgaWYgKGZpZWxkVmFsdWVbY21wXSB8fCBmaWVsZFZhbHVlW2NtcF0gPT09IDApIHtcbiAgICAgICAgY29uc3QgcGdDb21wYXJhdG9yID0gUGFyc2VUb1Bvc2dyZXNDb21wYXJhdG9yW2NtcF07XG4gICAgICAgIGNvbnN0IHBvc3RncmVzVmFsdWUgPSB0b1Bvc3RncmVzVmFsdWUoZmllbGRWYWx1ZVtjbXBdKTtcbiAgICAgICAgbGV0IGNvbnN0cmFpbnRGaWVsZE5hbWU7XG4gICAgICAgIGlmIChmaWVsZE5hbWUuaW5kZXhPZignLicpID49IDApIHtcbiAgICAgICAgICBsZXQgY2FzdFR5cGU7XG4gICAgICAgICAgc3dpdGNoICh0eXBlb2YgcG9zdGdyZXNWYWx1ZSkge1xuICAgICAgICAgICAgY2FzZSAnbnVtYmVyJzpcbiAgICAgICAgICAgICAgY2FzdFR5cGUgPSAnZG91YmxlIHByZWNpc2lvbic7XG4gICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgY2FzZSAnYm9vbGVhbic6XG4gICAgICAgICAgICAgIGNhc3RUeXBlID0gJ2Jvb2xlYW4nO1xuICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgIGNhc3RUeXBlID0gdW5kZWZpbmVkO1xuICAgICAgICAgIH1cbiAgICAgICAgICBjb25zdHJhaW50RmllbGROYW1lID0gY2FzdFR5cGVcbiAgICAgICAgICAgID8gYENBU1QgKCgke3RyYW5zZm9ybURvdEZpZWxkKGZpZWxkTmFtZSl9KSBBUyAke2Nhc3RUeXBlfSlgXG4gICAgICAgICAgICA6IHRyYW5zZm9ybURvdEZpZWxkKGZpZWxkTmFtZSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgY29uc3RyYWludEZpZWxkTmFtZSA9IGAkJHtpbmRleCsrfTpuYW1lYDtcbiAgICAgICAgICB2YWx1ZXMucHVzaChmaWVsZE5hbWUpO1xuICAgICAgICB9XG4gICAgICAgIHZhbHVlcy5wdXNoKHBvc3RncmVzVmFsdWUpO1xuICAgICAgICBwYXR0ZXJucy5wdXNoKGAke2NvbnN0cmFpbnRGaWVsZE5hbWV9ICR7cGdDb21wYXJhdG9yfSAkJHtpbmRleCsrfWApO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgaWYgKGluaXRpYWxQYXR0ZXJuc0xlbmd0aCA9PT0gcGF0dGVybnMubGVuZ3RoKSB7XG4gICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgIFBhcnNlLkVycm9yLk9QRVJBVElPTl9GT1JCSURERU4sXG4gICAgICAgIGBQb3N0Z3JlcyBkb2Vzbid0IHN1cHBvcnQgdGhpcyBxdWVyeSB0eXBlIHlldCAke0pTT04uc3RyaW5naWZ5KGZpZWxkVmFsdWUpfWBcbiAgICAgICk7XG4gICAgfVxuICB9XG4gIHZhbHVlcyA9IHZhbHVlcy5tYXAodHJhbnNmb3JtVmFsdWUpO1xuICByZXR1cm4geyBwYXR0ZXJuOiBwYXR0ZXJucy5qb2luKCcgQU5EICcpLCB2YWx1ZXMsIHNvcnRzIH07XG59O1xuXG5leHBvcnQgY2xhc3MgUG9zdGdyZXNTdG9yYWdlQWRhcHRlciBpbXBsZW1lbnRzIFN0b3JhZ2VBZGFwdGVyIHtcbiAgY2FuU29ydE9uSm9pblRhYmxlczogYm9vbGVhbjtcbiAgZW5hYmxlU2NoZW1hSG9va3M6IGJvb2xlYW47XG5cbiAgLy8gUHJpdmF0ZVxuICBfY29sbGVjdGlvblByZWZpeDogc3RyaW5nO1xuICBfY2xpZW50OiBhbnk7XG4gIF9vbmNoYW5nZTogYW55O1xuICBfcGdwOiBhbnk7XG4gIF9zdHJlYW06IGFueTtcbiAgX3V1aWQ6IGFueTtcblxuICBjb25zdHJ1Y3Rvcih7IHVyaSwgY29sbGVjdGlvblByZWZpeCA9ICcnLCBkYXRhYmFzZU9wdGlvbnMgPSB7fSB9OiBhbnkpIHtcbiAgICB0aGlzLl9jb2xsZWN0aW9uUHJlZml4ID0gY29sbGVjdGlvblByZWZpeDtcbiAgICB0aGlzLmVuYWJsZVNjaGVtYUhvb2tzID0gISFkYXRhYmFzZU9wdGlvbnMuZW5hYmxlU2NoZW1hSG9va3M7XG4gICAgZGVsZXRlIGRhdGFiYXNlT3B0aW9ucy5lbmFibGVTY2hlbWFIb29rcztcblxuICAgIGNvbnN0IHsgY2xpZW50LCBwZ3AgfSA9IGNyZWF0ZUNsaWVudCh1cmksIGRhdGFiYXNlT3B0aW9ucyk7XG4gICAgdGhpcy5fY2xpZW50ID0gY2xpZW50O1xuICAgIHRoaXMuX29uY2hhbmdlID0gKCkgPT4ge307XG4gICAgdGhpcy5fcGdwID0gcGdwO1xuICAgIHRoaXMuX3V1aWQgPSB1dWlkdjQoKTtcbiAgICB0aGlzLmNhblNvcnRPbkpvaW5UYWJsZXMgPSBmYWxzZTtcbiAgfVxuXG4gIHdhdGNoKGNhbGxiYWNrOiAoKSA9PiB2b2lkKTogdm9pZCB7XG4gICAgdGhpcy5fb25jaGFuZ2UgPSBjYWxsYmFjaztcbiAgfVxuXG4gIC8vTm90ZSB0aGF0IGFuYWx5emU9dHJ1ZSB3aWxsIHJ1biB0aGUgcXVlcnksIGV4ZWN1dGluZyBJTlNFUlRTLCBERUxFVEVTLCBldGMuXG4gIGNyZWF0ZUV4cGxhaW5hYmxlUXVlcnkocXVlcnk6IHN0cmluZywgYW5hbHl6ZTogYm9vbGVhbiA9IGZhbHNlKSB7XG4gICAgaWYgKGFuYWx5emUpIHtcbiAgICAgIHJldHVybiAnRVhQTEFJTiAoQU5BTFlaRSwgRk9STUFUIEpTT04pICcgKyBxdWVyeTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuICdFWFBMQUlOIChGT1JNQVQgSlNPTikgJyArIHF1ZXJ5O1xuICAgIH1cbiAgfVxuXG4gIGhhbmRsZVNodXRkb3duKCkge1xuICAgIGlmICh0aGlzLl9zdHJlYW0pIHtcbiAgICAgIHRoaXMuX3N0cmVhbS5kb25lKCk7XG4gICAgICBkZWxldGUgdGhpcy5fc3RyZWFtO1xuICAgIH1cbiAgICBpZiAoIXRoaXMuX2NsaWVudCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICB0aGlzLl9jbGllbnQuJHBvb2wuZW5kKCk7XG4gIH1cblxuICBhc3luYyBfbGlzdGVuVG9TY2hlbWEoKSB7XG4gICAgaWYgKCF0aGlzLl9zdHJlYW0gJiYgdGhpcy5lbmFibGVTY2hlbWFIb29rcykge1xuICAgICAgdGhpcy5fc3RyZWFtID0gYXdhaXQgdGhpcy5fY2xpZW50LmNvbm5lY3QoeyBkaXJlY3Q6IHRydWUgfSk7XG4gICAgICB0aGlzLl9zdHJlYW0uY2xpZW50Lm9uKCdub3RpZmljYXRpb24nLCBkYXRhID0+IHtcbiAgICAgICAgY29uc3QgcGF5bG9hZCA9IEpTT04ucGFyc2UoZGF0YS5wYXlsb2FkKTtcbiAgICAgICAgaWYgKHBheWxvYWQuc2VuZGVySWQgIT09IHRoaXMuX3V1aWQpIHtcbiAgICAgICAgICB0aGlzLl9vbmNoYW5nZSgpO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICAgIGF3YWl0IHRoaXMuX3N0cmVhbS5ub25lKCdMSVNURU4gJDF+JywgJ3NjaGVtYS5jaGFuZ2UnKTtcbiAgICB9XG4gIH1cblxuICBfbm90aWZ5U2NoZW1hQ2hhbmdlKCkge1xuICAgIGlmICh0aGlzLl9zdHJlYW0pIHtcbiAgICAgIHRoaXMuX3N0cmVhbVxuICAgICAgICAubm9uZSgnTk9USUZZICQxfiwgJDInLCBbJ3NjaGVtYS5jaGFuZ2UnLCB7IHNlbmRlcklkOiB0aGlzLl91dWlkIH1dKVxuICAgICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICAgIGNvbnNvbGUubG9nKCdGYWlsZWQgdG8gTm90aWZ5OicsIGVycm9yKTsgLy8gdW5saWtlbHkgdG8gZXZlciBoYXBwZW5cbiAgICAgICAgfSk7XG4gICAgfVxuICB9XG5cbiAgYXN5bmMgX2Vuc3VyZVNjaGVtYUNvbGxlY3Rpb25FeGlzdHMoY29ubjogYW55KSB7XG4gICAgY29ubiA9IGNvbm4gfHwgdGhpcy5fY2xpZW50O1xuICAgIGF3YWl0IGNvbm5cbiAgICAgIC5ub25lKFxuICAgICAgICAnQ1JFQVRFIFRBQkxFIElGIE5PVCBFWElTVFMgXCJfU0NIRU1BXCIgKCBcImNsYXNzTmFtZVwiIHZhckNoYXIoMTIwKSwgXCJzY2hlbWFcIiBqc29uYiwgXCJpc1BhcnNlQ2xhc3NcIiBib29sLCBQUklNQVJZIEtFWSAoXCJjbGFzc05hbWVcIikgKSdcbiAgICAgIClcbiAgICAgIC5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgIGlmIChcbiAgICAgICAgICBlcnJvci5jb2RlID09PSBQb3N0Z3Jlc0R1cGxpY2F0ZVJlbGF0aW9uRXJyb3IgfHxcbiAgICAgICAgICBlcnJvci5jb2RlID09PSBQb3N0Z3Jlc1VuaXF1ZUluZGV4VmlvbGF0aW9uRXJyb3IgfHxcbiAgICAgICAgICBlcnJvci5jb2RlID09PSBQb3N0Z3Jlc0R1cGxpY2F0ZU9iamVjdEVycm9yXG4gICAgICAgICkge1xuICAgICAgICAgIC8vIFRhYmxlIGFscmVhZHkgZXhpc3RzLCBtdXN0IGhhdmUgYmVlbiBjcmVhdGVkIGJ5IGEgZGlmZmVyZW50IHJlcXVlc3QuIElnbm9yZSBlcnJvci5cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gIH1cblxuICBhc3luYyBjbGFzc0V4aXN0cyhuYW1lOiBzdHJpbmcpIHtcbiAgICByZXR1cm4gdGhpcy5fY2xpZW50Lm9uZShcbiAgICAgICdTRUxFQ1QgRVhJU1RTIChTRUxFQ1QgMSBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS50YWJsZXMgV0hFUkUgdGFibGVfbmFtZSA9ICQxKScsXG4gICAgICBbbmFtZV0sXG4gICAgICBhID0+IGEuZXhpc3RzXG4gICAgKTtcbiAgfVxuXG4gIGFzeW5jIHNldENsYXNzTGV2ZWxQZXJtaXNzaW9ucyhjbGFzc05hbWU6IHN0cmluZywgQ0xQczogYW55KSB7XG4gICAgYXdhaXQgdGhpcy5fY2xpZW50LnRhc2soJ3NldC1jbGFzcy1sZXZlbC1wZXJtaXNzaW9ucycsIGFzeW5jIHQgPT4ge1xuICAgICAgY29uc3QgdmFsdWVzID0gW2NsYXNzTmFtZSwgJ3NjaGVtYScsICdjbGFzc0xldmVsUGVybWlzc2lvbnMnLCBKU09OLnN0cmluZ2lmeShDTFBzKV07XG4gICAgICBhd2FpdCB0Lm5vbmUoXG4gICAgICAgIGBVUERBVEUgXCJfU0NIRU1BXCIgU0VUICQyOm5hbWUgPSBqc29uX29iamVjdF9zZXRfa2V5KCQyOm5hbWUsICQzOjp0ZXh0LCAkNDo6anNvbmIpIFdIRVJFIFwiY2xhc3NOYW1lXCIgPSAkMWAsXG4gICAgICAgIHZhbHVlc1xuICAgICAgKTtcbiAgICB9KTtcbiAgICB0aGlzLl9ub3RpZnlTY2hlbWFDaGFuZ2UoKTtcbiAgfVxuXG4gIGFzeW5jIHNldEluZGV4ZXNXaXRoU2NoZW1hRm9ybWF0KFxuICAgIGNsYXNzTmFtZTogc3RyaW5nLFxuICAgIHN1Ym1pdHRlZEluZGV4ZXM6IGFueSxcbiAgICBleGlzdGluZ0luZGV4ZXM6IGFueSA9IHt9LFxuICAgIGZpZWxkczogYW55LFxuICAgIGNvbm46ID9hbnlcbiAgKTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29ubiA9IGNvbm4gfHwgdGhpcy5fY2xpZW50O1xuICAgIGNvbnN0IHNlbGYgPSB0aGlzO1xuICAgIGlmIChzdWJtaXR0ZWRJbmRleGVzID09PSB1bmRlZmluZWQpIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcbiAgICB9XG4gICAgaWYgKE9iamVjdC5rZXlzKGV4aXN0aW5nSW5kZXhlcykubGVuZ3RoID09PSAwKSB7XG4gICAgICBleGlzdGluZ0luZGV4ZXMgPSB7IF9pZF86IHsgX2lkOiAxIH0gfTtcbiAgICB9XG4gICAgY29uc3QgZGVsZXRlZEluZGV4ZXMgPSBbXTtcbiAgICBjb25zdCBpbnNlcnRlZEluZGV4ZXMgPSBbXTtcbiAgICBPYmplY3Qua2V5cyhzdWJtaXR0ZWRJbmRleGVzKS5mb3JFYWNoKG5hbWUgPT4ge1xuICAgICAgY29uc3QgZmllbGQgPSBzdWJtaXR0ZWRJbmRleGVzW25hbWVdO1xuICAgICAgaWYgKGV4aXN0aW5nSW5kZXhlc1tuYW1lXSAmJiBmaWVsZC5fX29wICE9PSAnRGVsZXRlJykge1xuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9RVUVSWSwgYEluZGV4ICR7bmFtZX0gZXhpc3RzLCBjYW5ub3QgdXBkYXRlLmApO1xuICAgICAgfVxuICAgICAgaWYgKCFleGlzdGluZ0luZGV4ZXNbbmFtZV0gJiYgZmllbGQuX19vcCA9PT0gJ0RlbGV0ZScpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgIFBhcnNlLkVycm9yLklOVkFMSURfUVVFUlksXG4gICAgICAgICAgYEluZGV4ICR7bmFtZX0gZG9lcyBub3QgZXhpc3QsIGNhbm5vdCBkZWxldGUuYFxuICAgICAgICApO1xuICAgICAgfVxuICAgICAgaWYgKGZpZWxkLl9fb3AgPT09ICdEZWxldGUnKSB7XG4gICAgICAgIGRlbGV0ZWRJbmRleGVzLnB1c2gobmFtZSk7XG4gICAgICAgIGRlbGV0ZSBleGlzdGluZ0luZGV4ZXNbbmFtZV07XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBPYmplY3Qua2V5cyhmaWVsZCkuZm9yRWFjaChrZXkgPT4ge1xuICAgICAgICAgIGlmICghT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKGZpZWxkcywga2V5KSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgICBQYXJzZS5FcnJvci5JTlZBTElEX1FVRVJZLFxuICAgICAgICAgICAgICBgRmllbGQgJHtrZXl9IGRvZXMgbm90IGV4aXN0LCBjYW5ub3QgYWRkIGluZGV4LmBcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgZXhpc3RpbmdJbmRleGVzW25hbWVdID0gZmllbGQ7XG4gICAgICAgIGluc2VydGVkSW5kZXhlcy5wdXNoKHtcbiAgICAgICAgICBrZXk6IGZpZWxkLFxuICAgICAgICAgIG5hbWUsXG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgIH0pO1xuICAgIGF3YWl0IGNvbm4udHgoJ3NldC1pbmRleGVzLXdpdGgtc2NoZW1hLWZvcm1hdCcsIGFzeW5jIHQgPT4ge1xuICAgICAgaWYgKGluc2VydGVkSW5kZXhlcy5sZW5ndGggPiAwKSB7XG4gICAgICAgIGF3YWl0IHNlbGYuY3JlYXRlSW5kZXhlcyhjbGFzc05hbWUsIGluc2VydGVkSW5kZXhlcywgdCk7XG4gICAgICB9XG4gICAgICBpZiAoZGVsZXRlZEluZGV4ZXMubGVuZ3RoID4gMCkge1xuICAgICAgICBhd2FpdCBzZWxmLmRyb3BJbmRleGVzKGNsYXNzTmFtZSwgZGVsZXRlZEluZGV4ZXMsIHQpO1xuICAgICAgfVxuICAgICAgYXdhaXQgdC5ub25lKFxuICAgICAgICAnVVBEQVRFIFwiX1NDSEVNQVwiIFNFVCAkMjpuYW1lID0ganNvbl9vYmplY3Rfc2V0X2tleSgkMjpuYW1lLCAkMzo6dGV4dCwgJDQ6Ompzb25iKSBXSEVSRSBcImNsYXNzTmFtZVwiID0gJDEnLFxuICAgICAgICBbY2xhc3NOYW1lLCAnc2NoZW1hJywgJ2luZGV4ZXMnLCBKU09OLnN0cmluZ2lmeShleGlzdGluZ0luZGV4ZXMpXVxuICAgICAgKTtcbiAgICB9KTtcbiAgICB0aGlzLl9ub3RpZnlTY2hlbWFDaGFuZ2UoKTtcbiAgfVxuXG4gIGFzeW5jIGNyZWF0ZUNsYXNzKGNsYXNzTmFtZTogc3RyaW5nLCBzY2hlbWE6IFNjaGVtYVR5cGUsIGNvbm46ID9hbnkpIHtcbiAgICBjb25uID0gY29ubiB8fCB0aGlzLl9jbGllbnQ7XG4gICAgY29uc3QgcGFyc2VTY2hlbWEgPSBhd2FpdCBjb25uXG4gICAgICAudHgoJ2NyZWF0ZS1jbGFzcycsIGFzeW5jIHQgPT4ge1xuICAgICAgICBhd2FpdCB0aGlzLmNyZWF0ZVRhYmxlKGNsYXNzTmFtZSwgc2NoZW1hLCB0KTtcbiAgICAgICAgYXdhaXQgdC5ub25lKFxuICAgICAgICAgICdJTlNFUlQgSU5UTyBcIl9TQ0hFTUFcIiAoXCJjbGFzc05hbWVcIiwgXCJzY2hlbWFcIiwgXCJpc1BhcnNlQ2xhc3NcIikgVkFMVUVTICgkPGNsYXNzTmFtZT4sICQ8c2NoZW1hPiwgdHJ1ZSknLFxuICAgICAgICAgIHsgY2xhc3NOYW1lLCBzY2hlbWEgfVxuICAgICAgICApO1xuICAgICAgICBhd2FpdCB0aGlzLnNldEluZGV4ZXNXaXRoU2NoZW1hRm9ybWF0KGNsYXNzTmFtZSwgc2NoZW1hLmluZGV4ZXMsIHt9LCBzY2hlbWEuZmllbGRzLCB0KTtcbiAgICAgICAgcmV0dXJuIHRvUGFyc2VTY2hlbWEoc2NoZW1hKTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goZXJyID0+IHtcbiAgICAgICAgaWYgKGVyci5jb2RlID09PSBQb3N0Z3Jlc1VuaXF1ZUluZGV4VmlvbGF0aW9uRXJyb3IgJiYgZXJyLmRldGFpbC5pbmNsdWRlcyhjbGFzc05hbWUpKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLkRVUExJQ0FURV9WQUxVRSwgYENsYXNzICR7Y2xhc3NOYW1lfSBhbHJlYWR5IGV4aXN0cy5gKTtcbiAgICAgICAgfVxuICAgICAgICB0aHJvdyBlcnI7XG4gICAgICB9KTtcbiAgICB0aGlzLl9ub3RpZnlTY2hlbWFDaGFuZ2UoKTtcbiAgICByZXR1cm4gcGFyc2VTY2hlbWE7XG4gIH1cblxuICAvLyBKdXN0IGNyZWF0ZSBhIHRhYmxlLCBkbyBub3QgaW5zZXJ0IGluIHNjaGVtYVxuICBhc3luYyBjcmVhdGVUYWJsZShjbGFzc05hbWU6IHN0cmluZywgc2NoZW1hOiBTY2hlbWFUeXBlLCBjb25uOiBhbnkpIHtcbiAgICBjb25uID0gY29ubiB8fCB0aGlzLl9jbGllbnQ7XG4gICAgZGVidWcoJ2NyZWF0ZVRhYmxlJyk7XG4gICAgY29uc3QgdmFsdWVzQXJyYXkgPSBbXTtcbiAgICBjb25zdCBwYXR0ZXJuc0FycmF5ID0gW107XG4gICAgY29uc3QgZmllbGRzID0gT2JqZWN0LmFzc2lnbih7fSwgc2NoZW1hLmZpZWxkcyk7XG4gICAgaWYgKGNsYXNzTmFtZSA9PT0gJ19Vc2VyJykge1xuICAgICAgZmllbGRzLl9lbWFpbF92ZXJpZnlfdG9rZW5fZXhwaXJlc19hdCA9IHsgdHlwZTogJ0RhdGUnIH07XG4gICAgICBmaWVsZHMuX2VtYWlsX3ZlcmlmeV90b2tlbiA9IHsgdHlwZTogJ1N0cmluZycgfTtcbiAgICAgIGZpZWxkcy5fYWNjb3VudF9sb2Nrb3V0X2V4cGlyZXNfYXQgPSB7IHR5cGU6ICdEYXRlJyB9O1xuICAgICAgZmllbGRzLl9mYWlsZWRfbG9naW5fY291bnQgPSB7IHR5cGU6ICdOdW1iZXInIH07XG4gICAgICBmaWVsZHMuX3BlcmlzaGFibGVfdG9rZW4gPSB7IHR5cGU6ICdTdHJpbmcnIH07XG4gICAgICBmaWVsZHMuX3BlcmlzaGFibGVfdG9rZW5fZXhwaXJlc19hdCA9IHsgdHlwZTogJ0RhdGUnIH07XG4gICAgICBmaWVsZHMuX3Bhc3N3b3JkX2NoYW5nZWRfYXQgPSB7IHR5cGU6ICdEYXRlJyB9O1xuICAgICAgZmllbGRzLl9wYXNzd29yZF9oaXN0b3J5ID0geyB0eXBlOiAnQXJyYXknIH07XG4gICAgfVxuICAgIGxldCBpbmRleCA9IDI7XG4gICAgY29uc3QgcmVsYXRpb25zID0gW107XG4gICAgT2JqZWN0LmtleXMoZmllbGRzKS5mb3JFYWNoKGZpZWxkTmFtZSA9PiB7XG4gICAgICBjb25zdCBwYXJzZVR5cGUgPSBmaWVsZHNbZmllbGROYW1lXTtcbiAgICAgIC8vIFNraXAgd2hlbiBpdCdzIGEgcmVsYXRpb25cbiAgICAgIC8vIFdlJ2xsIGNyZWF0ZSB0aGUgdGFibGVzIGxhdGVyXG4gICAgICBpZiAocGFyc2VUeXBlLnR5cGUgPT09ICdSZWxhdGlvbicpIHtcbiAgICAgICAgcmVsYXRpb25zLnB1c2goZmllbGROYW1lKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgaWYgKFsnX3JwZXJtJywgJ193cGVybSddLmluZGV4T2YoZmllbGROYW1lKSA+PSAwKSB7XG4gICAgICAgIHBhcnNlVHlwZS5jb250ZW50cyA9IHsgdHlwZTogJ1N0cmluZycgfTtcbiAgICAgIH1cbiAgICAgIHZhbHVlc0FycmF5LnB1c2goZmllbGROYW1lKTtcbiAgICAgIHZhbHVlc0FycmF5LnB1c2gocGFyc2VUeXBlVG9Qb3N0Z3Jlc1R5cGUocGFyc2VUeXBlKSk7XG4gICAgICBwYXR0ZXJuc0FycmF5LnB1c2goYCQke2luZGV4fTpuYW1lICQke2luZGV4ICsgMX06cmF3YCk7XG4gICAgICBpZiAoZmllbGROYW1lID09PSAnb2JqZWN0SWQnKSB7XG4gICAgICAgIHBhdHRlcm5zQXJyYXkucHVzaChgUFJJTUFSWSBLRVkgKCQke2luZGV4fTpuYW1lKWApO1xuICAgICAgfVxuICAgICAgaW5kZXggPSBpbmRleCArIDI7XG4gICAgfSk7XG4gICAgY29uc3QgcXMgPSBgQ1JFQVRFIFRBQkxFIElGIE5PVCBFWElTVFMgJDE6bmFtZSAoJHtwYXR0ZXJuc0FycmF5LmpvaW4oKX0pYDtcbiAgICBjb25zdCB2YWx1ZXMgPSBbY2xhc3NOYW1lLCAuLi52YWx1ZXNBcnJheV07XG5cbiAgICByZXR1cm4gY29ubi50YXNrKCdjcmVhdGUtdGFibGUnLCBhc3luYyB0ID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGF3YWl0IHQubm9uZShxcywgdmFsdWVzKTtcbiAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvci5jb2RlICE9PSBQb3N0Z3Jlc0R1cGxpY2F0ZVJlbGF0aW9uRXJyb3IpIHtcbiAgICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgICAgfVxuICAgICAgICAvLyBFTFNFOiBUYWJsZSBhbHJlYWR5IGV4aXN0cywgbXVzdCBoYXZlIGJlZW4gY3JlYXRlZCBieSBhIGRpZmZlcmVudCByZXF1ZXN0LiBJZ25vcmUgdGhlIGVycm9yLlxuICAgICAgfVxuICAgICAgYXdhaXQgdC50eCgnY3JlYXRlLXRhYmxlLXR4JywgdHggPT4ge1xuICAgICAgICByZXR1cm4gdHguYmF0Y2goXG4gICAgICAgICAgcmVsYXRpb25zLm1hcChmaWVsZE5hbWUgPT4ge1xuICAgICAgICAgICAgcmV0dXJuIHR4Lm5vbmUoXG4gICAgICAgICAgICAgICdDUkVBVEUgVEFCTEUgSUYgTk9UIEVYSVNUUyAkPGpvaW5UYWJsZTpuYW1lPiAoXCJyZWxhdGVkSWRcIiB2YXJDaGFyKDEyMCksIFwib3duaW5nSWRcIiB2YXJDaGFyKDEyMCksIFBSSU1BUlkgS0VZKFwicmVsYXRlZElkXCIsIFwib3duaW5nSWRcIikgKScsXG4gICAgICAgICAgICAgIHsgam9pblRhYmxlOiBgX0pvaW46JHtmaWVsZE5hbWV9OiR7Y2xhc3NOYW1lfWAgfVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9KVxuICAgICAgICApO1xuICAgICAgfSk7XG4gICAgfSk7XG4gIH1cblxuICBhc3luYyBzY2hlbWFVcGdyYWRlKGNsYXNzTmFtZTogc3RyaW5nLCBzY2hlbWE6IFNjaGVtYVR5cGUsIGNvbm46IGFueSkge1xuICAgIGRlYnVnKCdzY2hlbWFVcGdyYWRlJyk7XG4gICAgY29ubiA9IGNvbm4gfHwgdGhpcy5fY2xpZW50O1xuICAgIGNvbnN0IHNlbGYgPSB0aGlzO1xuXG4gICAgYXdhaXQgY29ubi50eCgnc2NoZW1hLXVwZ3JhZGUnLCBhc3luYyB0ID0+IHtcbiAgICAgIGNvbnN0IGNvbHVtbnMgPSBhd2FpdCB0Lm1hcChcbiAgICAgICAgJ1NFTEVDVCBjb2x1bW5fbmFtZSBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS5jb2x1bW5zIFdIRVJFIHRhYmxlX25hbWUgPSAkPGNsYXNzTmFtZT4nLFxuICAgICAgICB7IGNsYXNzTmFtZSB9LFxuICAgICAgICBhID0+IGEuY29sdW1uX25hbWVcbiAgICAgICk7XG4gICAgICBjb25zdCBuZXdDb2x1bW5zID0gT2JqZWN0LmtleXMoc2NoZW1hLmZpZWxkcylcbiAgICAgICAgLmZpbHRlcihpdGVtID0+IGNvbHVtbnMuaW5kZXhPZihpdGVtKSA9PT0gLTEpXG4gICAgICAgIC5tYXAoZmllbGROYW1lID0+XG4gICAgICAgICAgc2VsZi5hZGRGaWVsZElmTm90RXhpc3RzKGNsYXNzTmFtZSwgZmllbGROYW1lLCBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0sIHQpXG4gICAgICAgICk7XG5cbiAgICAgIGF3YWl0IHQuYmF0Y2gobmV3Q29sdW1ucyk7XG4gICAgfSk7XG4gIH1cblxuICBhc3luYyBhZGRGaWVsZElmTm90RXhpc3RzKGNsYXNzTmFtZTogc3RyaW5nLCBmaWVsZE5hbWU6IHN0cmluZywgdHlwZTogYW55LCBjb25uOiBhbnkpIHtcbiAgICAvLyBUT0RPOiBNdXN0IGJlIHJldmlzZWQgZm9yIGludmFsaWQgbG9naWMuLi5cbiAgICBkZWJ1ZygnYWRkRmllbGRJZk5vdEV4aXN0cycpO1xuICAgIGNvbm4gPSBjb25uIHx8IHRoaXMuX2NsaWVudDtcbiAgICBjb25zdCBzZWxmID0gdGhpcztcbiAgICBhd2FpdCBjb25uLnR4KCdhZGQtZmllbGQtaWYtbm90LWV4aXN0cycsIGFzeW5jIHQgPT4ge1xuICAgICAgaWYgKHR5cGUudHlwZSAhPT0gJ1JlbGF0aW9uJykge1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGF3YWl0IHQubm9uZShcbiAgICAgICAgICAgICdBTFRFUiBUQUJMRSAkPGNsYXNzTmFtZTpuYW1lPiBBREQgQ09MVU1OIElGIE5PVCBFWElTVFMgJDxmaWVsZE5hbWU6bmFtZT4gJDxwb3N0Z3Jlc1R5cGU6cmF3PicsXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGNsYXNzTmFtZSxcbiAgICAgICAgICAgICAgZmllbGROYW1lLFxuICAgICAgICAgICAgICBwb3N0Z3Jlc1R5cGU6IHBhcnNlVHlwZVRvUG9zdGdyZXNUeXBlKHR5cGUpLFxuICAgICAgICAgICAgfVxuICAgICAgICAgICk7XG4gICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgaWYgKGVycm9yLmNvZGUgPT09IFBvc3RncmVzUmVsYXRpb25Eb2VzTm90RXhpc3RFcnJvcikge1xuICAgICAgICAgICAgcmV0dXJuIHNlbGYuY3JlYXRlQ2xhc3MoY2xhc3NOYW1lLCB7IGZpZWxkczogeyBbZmllbGROYW1lXTogdHlwZSB9IH0sIHQpO1xuICAgICAgICAgIH1cbiAgICAgICAgICBpZiAoZXJyb3IuY29kZSAhPT0gUG9zdGdyZXNEdXBsaWNhdGVDb2x1bW5FcnJvcikge1xuICAgICAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICAgICAgfVxuICAgICAgICAgIC8vIENvbHVtbiBhbHJlYWR5IGV4aXN0cywgY3JlYXRlZCBieSBvdGhlciByZXF1ZXN0LiBDYXJyeSBvbiB0byBzZWUgaWYgaXQncyB0aGUgcmlnaHQgdHlwZS5cbiAgICAgICAgfVxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgYXdhaXQgdC5ub25lKFxuICAgICAgICAgICdDUkVBVEUgVEFCTEUgSUYgTk9UIEVYSVNUUyAkPGpvaW5UYWJsZTpuYW1lPiAoXCJyZWxhdGVkSWRcIiB2YXJDaGFyKDEyMCksIFwib3duaW5nSWRcIiB2YXJDaGFyKDEyMCksIFBSSU1BUlkgS0VZKFwicmVsYXRlZElkXCIsIFwib3duaW5nSWRcIikgKScsXG4gICAgICAgICAgeyBqb2luVGFibGU6IGBfSm9pbjoke2ZpZWxkTmFtZX06JHtjbGFzc05hbWV9YCB9XG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IHJlc3VsdCA9IGF3YWl0IHQuYW55KFxuICAgICAgICAnU0VMRUNUIFwic2NoZW1hXCIgRlJPTSBcIl9TQ0hFTUFcIiBXSEVSRSBcImNsYXNzTmFtZVwiID0gJDxjbGFzc05hbWU+IGFuZCAoXCJzY2hlbWFcIjo6anNvbi0+XFwnZmllbGRzXFwnLT4kPGZpZWxkTmFtZT4pIGlzIG5vdCBudWxsJyxcbiAgICAgICAgeyBjbGFzc05hbWUsIGZpZWxkTmFtZSB9XG4gICAgICApO1xuXG4gICAgICBpZiAocmVzdWx0WzBdKSB7XG4gICAgICAgIHRocm93ICdBdHRlbXB0ZWQgdG8gYWRkIGEgZmllbGQgdGhhdCBhbHJlYWR5IGV4aXN0cyc7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb25zdCBwYXRoID0gYHtmaWVsZHMsJHtmaWVsZE5hbWV9fWA7XG4gICAgICAgIGF3YWl0IHQubm9uZShcbiAgICAgICAgICAnVVBEQVRFIFwiX1NDSEVNQVwiIFNFVCBcInNjaGVtYVwiPWpzb25iX3NldChcInNjaGVtYVwiLCAkPHBhdGg+LCAkPHR5cGU+KSAgV0hFUkUgXCJjbGFzc05hbWVcIj0kPGNsYXNzTmFtZT4nLFxuICAgICAgICAgIHsgcGF0aCwgdHlwZSwgY2xhc3NOYW1lIH1cbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgICB0aGlzLl9ub3RpZnlTY2hlbWFDaGFuZ2UoKTtcbiAgfVxuXG4gIC8vIERyb3BzIGEgY29sbGVjdGlvbi4gUmVzb2x2ZXMgd2l0aCB0cnVlIGlmIGl0IHdhcyBhIFBhcnNlIFNjaGVtYSAoZWcuIF9Vc2VyLCBDdXN0b20sIGV0Yy4pXG4gIC8vIGFuZCByZXNvbHZlcyB3aXRoIGZhbHNlIGlmIGl0IHdhc24ndCAoZWcuIGEgam9pbiB0YWJsZSkuIFJlamVjdHMgaWYgZGVsZXRpb24gd2FzIGltcG9zc2libGUuXG4gIGFzeW5jIGRlbGV0ZUNsYXNzKGNsYXNzTmFtZTogc3RyaW5nKSB7XG4gICAgY29uc3Qgb3BlcmF0aW9ucyA9IFtcbiAgICAgIHsgcXVlcnk6IGBEUk9QIFRBQkxFIElGIEVYSVNUUyAkMTpuYW1lYCwgdmFsdWVzOiBbY2xhc3NOYW1lXSB9LFxuICAgICAge1xuICAgICAgICBxdWVyeTogYERFTEVURSBGUk9NIFwiX1NDSEVNQVwiIFdIRVJFIFwiY2xhc3NOYW1lXCIgPSAkMWAsXG4gICAgICAgIHZhbHVlczogW2NsYXNzTmFtZV0sXG4gICAgICB9LFxuICAgIF07XG4gICAgY29uc3QgcmVzcG9uc2UgPSBhd2FpdCB0aGlzLl9jbGllbnRcbiAgICAgIC50eCh0ID0+IHQubm9uZSh0aGlzLl9wZ3AuaGVscGVycy5jb25jYXQob3BlcmF0aW9ucykpKVxuICAgICAgLnRoZW4oKCkgPT4gY2xhc3NOYW1lLmluZGV4T2YoJ19Kb2luOicpICE9IDApOyAvLyByZXNvbHZlcyB3aXRoIGZhbHNlIHdoZW4gX0pvaW4gdGFibGVcblxuICAgIHRoaXMuX25vdGlmeVNjaGVtYUNoYW5nZSgpO1xuICAgIHJldHVybiByZXNwb25zZTtcbiAgfVxuXG4gIC8vIERlbGV0ZSBhbGwgZGF0YSBrbm93biB0byB0aGlzIGFkYXB0ZXIuIFVzZWQgZm9yIHRlc3RpbmcuXG4gIGFzeW5jIGRlbGV0ZUFsbENsYXNzZXMoKSB7XG4gICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKS5nZXRUaW1lKCk7XG4gICAgY29uc3QgaGVscGVycyA9IHRoaXMuX3BncC5oZWxwZXJzO1xuICAgIGRlYnVnKCdkZWxldGVBbGxDbGFzc2VzJyk7XG5cbiAgICBhd2FpdCB0aGlzLl9jbGllbnRcbiAgICAgIC50YXNrKCdkZWxldGUtYWxsLWNsYXNzZXMnLCBhc3luYyB0ID0+IHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBjb25zdCByZXN1bHRzID0gYXdhaXQgdC5hbnkoJ1NFTEVDVCAqIEZST00gXCJfU0NIRU1BXCInKTtcbiAgICAgICAgICBjb25zdCBqb2lucyA9IHJlc3VsdHMucmVkdWNlKChsaXN0OiBBcnJheTxzdHJpbmc+LCBzY2hlbWE6IGFueSkgPT4ge1xuICAgICAgICAgICAgcmV0dXJuIGxpc3QuY29uY2F0KGpvaW5UYWJsZXNGb3JTY2hlbWEoc2NoZW1hLnNjaGVtYSkpO1xuICAgICAgICAgIH0sIFtdKTtcbiAgICAgICAgICBjb25zdCBjbGFzc2VzID0gW1xuICAgICAgICAgICAgJ19TQ0hFTUEnLFxuICAgICAgICAgICAgJ19QdXNoU3RhdHVzJyxcbiAgICAgICAgICAgICdfSm9iU3RhdHVzJyxcbiAgICAgICAgICAgICdfSm9iU2NoZWR1bGUnLFxuICAgICAgICAgICAgJ19Ib29rcycsXG4gICAgICAgICAgICAnX0dsb2JhbENvbmZpZycsXG4gICAgICAgICAgICAnX0dyYXBoUUxDb25maWcnLFxuICAgICAgICAgICAgJ19BdWRpZW5jZScsXG4gICAgICAgICAgICAnX0lkZW1wb3RlbmN5JyxcbiAgICAgICAgICAgIC4uLnJlc3VsdHMubWFwKHJlc3VsdCA9PiByZXN1bHQuY2xhc3NOYW1lKSxcbiAgICAgICAgICAgIC4uLmpvaW5zLFxuICAgICAgICAgIF07XG4gICAgICAgICAgY29uc3QgcXVlcmllcyA9IGNsYXNzZXMubWFwKGNsYXNzTmFtZSA9PiAoe1xuICAgICAgICAgICAgcXVlcnk6ICdEUk9QIFRBQkxFIElGIEVYSVNUUyAkPGNsYXNzTmFtZTpuYW1lPicsXG4gICAgICAgICAgICB2YWx1ZXM6IHsgY2xhc3NOYW1lIH0sXG4gICAgICAgICAgfSkpO1xuICAgICAgICAgIGF3YWl0IHQudHgodHggPT4gdHgubm9uZShoZWxwZXJzLmNvbmNhdChxdWVyaWVzKSkpO1xuICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgIGlmIChlcnJvci5jb2RlICE9PSBQb3N0Z3Jlc1JlbGF0aW9uRG9lc05vdEV4aXN0RXJyb3IpIHtcbiAgICAgICAgICAgIHRocm93IGVycm9yO1xuICAgICAgICAgIH1cbiAgICAgICAgICAvLyBObyBfU0NIRU1BIGNvbGxlY3Rpb24uIERvbid0IGRlbGV0ZSBhbnl0aGluZy5cbiAgICAgICAgfVxuICAgICAgfSlcbiAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgZGVidWcoYGRlbGV0ZUFsbENsYXNzZXMgZG9uZSBpbiAke25ldyBEYXRlKCkuZ2V0VGltZSgpIC0gbm93fWApO1xuICAgICAgfSk7XG4gIH1cblxuICAvLyBSZW1vdmUgdGhlIGNvbHVtbiBhbmQgYWxsIHRoZSBkYXRhLiBGb3IgUmVsYXRpb25zLCB0aGUgX0pvaW4gY29sbGVjdGlvbiBpcyBoYW5kbGVkXG4gIC8vIHNwZWNpYWxseSwgdGhpcyBmdW5jdGlvbiBkb2VzIG5vdCBkZWxldGUgX0pvaW4gY29sdW1ucy4gSXQgc2hvdWxkLCBob3dldmVyLCBpbmRpY2F0ZVxuICAvLyB0aGF0IHRoZSByZWxhdGlvbiBmaWVsZHMgZG9lcyBub3QgZXhpc3QgYW55bW9yZS4gSW4gbW9uZ28sIHRoaXMgbWVhbnMgcmVtb3ZpbmcgaXQgZnJvbVxuICAvLyB0aGUgX1NDSEVNQSBjb2xsZWN0aW9uLiAgVGhlcmUgc2hvdWxkIGJlIG5vIGFjdHVhbCBkYXRhIGluIHRoZSBjb2xsZWN0aW9uIHVuZGVyIHRoZSBzYW1lIG5hbWVcbiAgLy8gYXMgdGhlIHJlbGF0aW9uIGNvbHVtbiwgc28gaXQncyBmaW5lIHRvIGF0dGVtcHQgdG8gZGVsZXRlIGl0LiBJZiB0aGUgZmllbGRzIGxpc3RlZCB0byBiZVxuICAvLyBkZWxldGVkIGRvIG5vdCBleGlzdCwgdGhpcyBmdW5jdGlvbiBzaG91bGQgcmV0dXJuIHN1Y2Nlc3NmdWxseSBhbnl3YXlzLiBDaGVja2luZyBmb3JcbiAgLy8gYXR0ZW1wdHMgdG8gZGVsZXRlIG5vbi1leGlzdGVudCBmaWVsZHMgaXMgdGhlIHJlc3BvbnNpYmlsaXR5IG9mIFBhcnNlIFNlcnZlci5cblxuICAvLyBUaGlzIGZ1bmN0aW9uIGlzIG5vdCBvYmxpZ2F0ZWQgdG8gZGVsZXRlIGZpZWxkcyBhdG9taWNhbGx5LiBJdCBpcyBnaXZlbiB0aGUgZmllbGRcbiAgLy8gbmFtZXMgaW4gYSBsaXN0IHNvIHRoYXQgZGF0YWJhc2VzIHRoYXQgYXJlIGNhcGFibGUgb2YgZGVsZXRpbmcgZmllbGRzIGF0b21pY2FsbHlcbiAgLy8gbWF5IGRvIHNvLlxuXG4gIC8vIFJldHVybnMgYSBQcm9taXNlLlxuICBhc3luYyBkZWxldGVGaWVsZHMoY2xhc3NOYW1lOiBzdHJpbmcsIHNjaGVtYTogU2NoZW1hVHlwZSwgZmllbGROYW1lczogc3RyaW5nW10pOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBkZWJ1ZygnZGVsZXRlRmllbGRzJyk7XG4gICAgZmllbGROYW1lcyA9IGZpZWxkTmFtZXMucmVkdWNlKChsaXN0OiBBcnJheTxzdHJpbmc+LCBmaWVsZE5hbWU6IHN0cmluZykgPT4ge1xuICAgICAgY29uc3QgZmllbGQgPSBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV07XG4gICAgICBpZiAoZmllbGQudHlwZSAhPT0gJ1JlbGF0aW9uJykge1xuICAgICAgICBsaXN0LnB1c2goZmllbGROYW1lKTtcbiAgICAgIH1cbiAgICAgIGRlbGV0ZSBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV07XG4gICAgICByZXR1cm4gbGlzdDtcbiAgICB9LCBbXSk7XG5cbiAgICBjb25zdCB2YWx1ZXMgPSBbY2xhc3NOYW1lLCAuLi5maWVsZE5hbWVzXTtcbiAgICBjb25zdCBjb2x1bW5zID0gZmllbGROYW1lc1xuICAgICAgLm1hcCgobmFtZSwgaWR4KSA9PiB7XG4gICAgICAgIHJldHVybiBgJCR7aWR4ICsgMn06bmFtZWA7XG4gICAgICB9KVxuICAgICAgLmpvaW4oJywgRFJPUCBDT0xVTU4nKTtcblxuICAgIGF3YWl0IHRoaXMuX2NsaWVudC50eCgnZGVsZXRlLWZpZWxkcycsIGFzeW5jIHQgPT4ge1xuICAgICAgYXdhaXQgdC5ub25lKCdVUERBVEUgXCJfU0NIRU1BXCIgU0VUIFwic2NoZW1hXCIgPSAkPHNjaGVtYT4gV0hFUkUgXCJjbGFzc05hbWVcIiA9ICQ8Y2xhc3NOYW1lPicsIHtcbiAgICAgICAgc2NoZW1hLFxuICAgICAgICBjbGFzc05hbWUsXG4gICAgICB9KTtcbiAgICAgIGlmICh2YWx1ZXMubGVuZ3RoID4gMSkge1xuICAgICAgICBhd2FpdCB0Lm5vbmUoYEFMVEVSIFRBQkxFICQxOm5hbWUgRFJPUCBDT0xVTU4gSUYgRVhJU1RTICR7Y29sdW1uc31gLCB2YWx1ZXMpO1xuICAgICAgfVxuICAgIH0pO1xuICAgIHRoaXMuX25vdGlmeVNjaGVtYUNoYW5nZSgpO1xuICB9XG5cbiAgLy8gUmV0dXJuIGEgcHJvbWlzZSBmb3IgYWxsIHNjaGVtYXMga25vd24gdG8gdGhpcyBhZGFwdGVyLCBpbiBQYXJzZSBmb3JtYXQuIEluIGNhc2UgdGhlXG4gIC8vIHNjaGVtYXMgY2Fubm90IGJlIHJldHJpZXZlZCwgcmV0dXJucyBhIHByb21pc2UgdGhhdCByZWplY3RzLiBSZXF1aXJlbWVudHMgZm9yIHRoZVxuICAvLyByZWplY3Rpb24gcmVhc29uIGFyZSBUQkQuXG4gIGFzeW5jIGdldEFsbENsYXNzZXMoKSB7XG4gICAgcmV0dXJuIHRoaXMuX2NsaWVudC50YXNrKCdnZXQtYWxsLWNsYXNzZXMnLCBhc3luYyB0ID0+IHtcbiAgICAgIHJldHVybiBhd2FpdCB0Lm1hcCgnU0VMRUNUICogRlJPTSBcIl9TQ0hFTUFcIicsIG51bGwsIHJvdyA9PlxuICAgICAgICB0b1BhcnNlU2NoZW1hKHsgY2xhc3NOYW1lOiByb3cuY2xhc3NOYW1lLCAuLi5yb3cuc2NoZW1hIH0pXG4gICAgICApO1xuICAgIH0pO1xuICB9XG5cbiAgLy8gUmV0dXJuIGEgcHJvbWlzZSBmb3IgdGhlIHNjaGVtYSB3aXRoIHRoZSBnaXZlbiBuYW1lLCBpbiBQYXJzZSBmb3JtYXQuIElmXG4gIC8vIHRoaXMgYWRhcHRlciBkb2Vzbid0IGtub3cgYWJvdXQgdGhlIHNjaGVtYSwgcmV0dXJuIGEgcHJvbWlzZSB0aGF0IHJlamVjdHMgd2l0aFxuICAvLyB1bmRlZmluZWQgYXMgdGhlIHJlYXNvbi5cbiAgYXN5bmMgZ2V0Q2xhc3MoY2xhc3NOYW1lOiBzdHJpbmcpIHtcbiAgICBkZWJ1ZygnZ2V0Q2xhc3MnKTtcbiAgICByZXR1cm4gdGhpcy5fY2xpZW50XG4gICAgICAuYW55KCdTRUxFQ1QgKiBGUk9NIFwiX1NDSEVNQVwiIFdIRVJFIFwiY2xhc3NOYW1lXCIgPSAkPGNsYXNzTmFtZT4nLCB7XG4gICAgICAgIGNsYXNzTmFtZSxcbiAgICAgIH0pXG4gICAgICAudGhlbihyZXN1bHQgPT4ge1xuICAgICAgICBpZiAocmVzdWx0Lmxlbmd0aCAhPT0gMSkge1xuICAgICAgICAgIHRocm93IHVuZGVmaW5lZDtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcmVzdWx0WzBdLnNjaGVtYTtcbiAgICAgIH0pXG4gICAgICAudGhlbih0b1BhcnNlU2NoZW1hKTtcbiAgfVxuXG4gIC8vIFRPRE86IHJlbW92ZSB0aGUgbW9uZ28gZm9ybWF0IGRlcGVuZGVuY3kgaW4gdGhlIHJldHVybiB2YWx1ZVxuICBhc3luYyBjcmVhdGVPYmplY3QoXG4gICAgY2xhc3NOYW1lOiBzdHJpbmcsXG4gICAgc2NoZW1hOiBTY2hlbWFUeXBlLFxuICAgIG9iamVjdDogYW55LFxuICAgIHRyYW5zYWN0aW9uYWxTZXNzaW9uOiA/YW55XG4gICkge1xuICAgIGRlYnVnKCdjcmVhdGVPYmplY3QnKTtcbiAgICBsZXQgY29sdW1uc0FycmF5ID0gW107XG4gICAgY29uc3QgdmFsdWVzQXJyYXkgPSBbXTtcbiAgICBzY2hlbWEgPSB0b1Bvc3RncmVzU2NoZW1hKHNjaGVtYSk7XG4gICAgY29uc3QgZ2VvUG9pbnRzID0ge307XG5cbiAgICBvYmplY3QgPSBoYW5kbGVEb3RGaWVsZHMob2JqZWN0KTtcblxuICAgIHZhbGlkYXRlS2V5cyhvYmplY3QpO1xuXG4gICAgT2JqZWN0LmtleXMob2JqZWN0KS5mb3JFYWNoKGZpZWxkTmFtZSA9PiB7XG4gICAgICBpZiAob2JqZWN0W2ZpZWxkTmFtZV0gPT09IG51bGwpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgdmFyIGF1dGhEYXRhTWF0Y2ggPSBmaWVsZE5hbWUubWF0Y2goL15fYXV0aF9kYXRhXyhbYS16QS1aMC05X10rKSQvKTtcbiAgICAgIGlmIChhdXRoRGF0YU1hdGNoKSB7XG4gICAgICAgIHZhciBwcm92aWRlciA9IGF1dGhEYXRhTWF0Y2hbMV07XG4gICAgICAgIG9iamVjdFsnYXV0aERhdGEnXSA9IG9iamVjdFsnYXV0aERhdGEnXSB8fCB7fTtcbiAgICAgICAgb2JqZWN0WydhdXRoRGF0YSddW3Byb3ZpZGVyXSA9IG9iamVjdFtmaWVsZE5hbWVdO1xuICAgICAgICBkZWxldGUgb2JqZWN0W2ZpZWxkTmFtZV07XG4gICAgICAgIGZpZWxkTmFtZSA9ICdhdXRoRGF0YSc7XG4gICAgICB9XG5cbiAgICAgIGNvbHVtbnNBcnJheS5wdXNoKGZpZWxkTmFtZSk7XG4gICAgICBpZiAoIXNjaGVtYS5maWVsZHNbZmllbGROYW1lXSAmJiBjbGFzc05hbWUgPT09ICdfVXNlcicpIHtcbiAgICAgICAgaWYgKFxuICAgICAgICAgIGZpZWxkTmFtZSA9PT0gJ19lbWFpbF92ZXJpZnlfdG9rZW4nIHx8XG4gICAgICAgICAgZmllbGROYW1lID09PSAnX2ZhaWxlZF9sb2dpbl9jb3VudCcgfHxcbiAgICAgICAgICBmaWVsZE5hbWUgPT09ICdfcGVyaXNoYWJsZV90b2tlbicgfHxcbiAgICAgICAgICBmaWVsZE5hbWUgPT09ICdfcGFzc3dvcmRfaGlzdG9yeSdcbiAgICAgICAgKSB7XG4gICAgICAgICAgdmFsdWVzQXJyYXkucHVzaChvYmplY3RbZmllbGROYW1lXSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoZmllbGROYW1lID09PSAnX2VtYWlsX3ZlcmlmeV90b2tlbl9leHBpcmVzX2F0Jykge1xuICAgICAgICAgIGlmIChvYmplY3RbZmllbGROYW1lXSkge1xuICAgICAgICAgICAgdmFsdWVzQXJyYXkucHVzaChvYmplY3RbZmllbGROYW1lXS5pc28pO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICB2YWx1ZXNBcnJheS5wdXNoKG51bGwpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGlmIChcbiAgICAgICAgICBmaWVsZE5hbWUgPT09ICdfYWNjb3VudF9sb2Nrb3V0X2V4cGlyZXNfYXQnIHx8XG4gICAgICAgICAgZmllbGROYW1lID09PSAnX3BlcmlzaGFibGVfdG9rZW5fZXhwaXJlc19hdCcgfHxcbiAgICAgICAgICBmaWVsZE5hbWUgPT09ICdfcGFzc3dvcmRfY2hhbmdlZF9hdCdcbiAgICAgICAgKSB7XG4gICAgICAgICAgaWYgKG9iamVjdFtmaWVsZE5hbWVdKSB7XG4gICAgICAgICAgICB2YWx1ZXNBcnJheS5wdXNoKG9iamVjdFtmaWVsZE5hbWVdLmlzbyk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHZhbHVlc0FycmF5LnB1c2gobnVsbCk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICAgIHN3aXRjaCAoc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdLnR5cGUpIHtcbiAgICAgICAgY2FzZSAnRGF0ZSc6XG4gICAgICAgICAgaWYgKG9iamVjdFtmaWVsZE5hbWVdKSB7XG4gICAgICAgICAgICB2YWx1ZXNBcnJheS5wdXNoKG9iamVjdFtmaWVsZE5hbWVdLmlzbyk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHZhbHVlc0FycmF5LnB1c2gobnVsbCk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdQb2ludGVyJzpcbiAgICAgICAgICB2YWx1ZXNBcnJheS5wdXNoKG9iamVjdFtmaWVsZE5hbWVdLm9iamVjdElkKTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnQXJyYXknOlxuICAgICAgICAgIGlmIChbJ19ycGVybScsICdfd3Blcm0nXS5pbmRleE9mKGZpZWxkTmFtZSkgPj0gMCkge1xuICAgICAgICAgICAgdmFsdWVzQXJyYXkucHVzaChvYmplY3RbZmllbGROYW1lXSk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIHZhbHVlc0FycmF5LnB1c2goSlNPTi5zdHJpbmdpZnkob2JqZWN0W2ZpZWxkTmFtZV0pKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ09iamVjdCc6XG4gICAgICAgIGNhc2UgJ0J5dGVzJzpcbiAgICAgICAgY2FzZSAnU3RyaW5nJzpcbiAgICAgICAgY2FzZSAnTnVtYmVyJzpcbiAgICAgICAgY2FzZSAnQm9vbGVhbic6XG4gICAgICAgICAgdmFsdWVzQXJyYXkucHVzaChvYmplY3RbZmllbGROYW1lXSk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ0ZpbGUnOlxuICAgICAgICAgIHZhbHVlc0FycmF5LnB1c2gob2JqZWN0W2ZpZWxkTmFtZV0ubmFtZSk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ1BvbHlnb24nOiB7XG4gICAgICAgICAgY29uc3QgdmFsdWUgPSBjb252ZXJ0UG9seWdvblRvU1FMKG9iamVjdFtmaWVsZE5hbWVdLmNvb3JkaW5hdGVzKTtcbiAgICAgICAgICB2YWx1ZXNBcnJheS5wdXNoKHZhbHVlKTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgICBjYXNlICdHZW9Qb2ludCc6XG4gICAgICAgICAgLy8gcG9wIHRoZSBwb2ludCBhbmQgcHJvY2VzcyBsYXRlclxuICAgICAgICAgIGdlb1BvaW50c1tmaWVsZE5hbWVdID0gb2JqZWN0W2ZpZWxkTmFtZV07XG4gICAgICAgICAgY29sdW1uc0FycmF5LnBvcCgpO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgIHRocm93IGBUeXBlICR7c2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdLnR5cGV9IG5vdCBzdXBwb3J0ZWQgeWV0YDtcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIGNvbHVtbnNBcnJheSA9IGNvbHVtbnNBcnJheS5jb25jYXQoT2JqZWN0LmtleXMoZ2VvUG9pbnRzKSk7XG4gICAgY29uc3QgaW5pdGlhbFZhbHVlcyA9IHZhbHVlc0FycmF5Lm1hcCgodmFsLCBpbmRleCkgPT4ge1xuICAgICAgbGV0IHRlcm1pbmF0aW9uID0gJyc7XG4gICAgICBjb25zdCBmaWVsZE5hbWUgPSBjb2x1bW5zQXJyYXlbaW5kZXhdO1xuICAgICAgaWYgKFsnX3JwZXJtJywgJ193cGVybSddLmluZGV4T2YoZmllbGROYW1lKSA+PSAwKSB7XG4gICAgICAgIHRlcm1pbmF0aW9uID0gJzo6dGV4dFtdJztcbiAgICAgIH0gZWxzZSBpZiAoc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdICYmIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS50eXBlID09PSAnQXJyYXknKSB7XG4gICAgICAgIHRlcm1pbmF0aW9uID0gJzo6anNvbmInO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGAkJHtpbmRleCArIDIgKyBjb2x1bW5zQXJyYXkubGVuZ3RofSR7dGVybWluYXRpb259YDtcbiAgICB9KTtcbiAgICBjb25zdCBnZW9Qb2ludHNJbmplY3RzID0gT2JqZWN0LmtleXMoZ2VvUG9pbnRzKS5tYXAoa2V5ID0+IHtcbiAgICAgIGNvbnN0IHZhbHVlID0gZ2VvUG9pbnRzW2tleV07XG4gICAgICB2YWx1ZXNBcnJheS5wdXNoKHZhbHVlLmxvbmdpdHVkZSwgdmFsdWUubGF0aXR1ZGUpO1xuICAgICAgY29uc3QgbCA9IHZhbHVlc0FycmF5Lmxlbmd0aCArIGNvbHVtbnNBcnJheS5sZW5ndGg7XG4gICAgICByZXR1cm4gYFBPSU5UKCQke2x9LCAkJHtsICsgMX0pYDtcbiAgICB9KTtcblxuICAgIGNvbnN0IGNvbHVtbnNQYXR0ZXJuID0gY29sdW1uc0FycmF5Lm1hcCgoY29sLCBpbmRleCkgPT4gYCQke2luZGV4ICsgMn06bmFtZWApLmpvaW4oKTtcbiAgICBjb25zdCB2YWx1ZXNQYXR0ZXJuID0gaW5pdGlhbFZhbHVlcy5jb25jYXQoZ2VvUG9pbnRzSW5qZWN0cykuam9pbigpO1xuXG4gICAgY29uc3QgcXMgPSBgSU5TRVJUIElOVE8gJDE6bmFtZSAoJHtjb2x1bW5zUGF0dGVybn0pIFZBTFVFUyAoJHt2YWx1ZXNQYXR0ZXJufSlgO1xuICAgIGNvbnN0IHZhbHVlcyA9IFtjbGFzc05hbWUsIC4uLmNvbHVtbnNBcnJheSwgLi4udmFsdWVzQXJyYXldO1xuICAgIGNvbnN0IHByb21pc2UgPSAodHJhbnNhY3Rpb25hbFNlc3Npb24gPyB0cmFuc2FjdGlvbmFsU2Vzc2lvbi50IDogdGhpcy5fY2xpZW50KVxuICAgICAgLm5vbmUocXMsIHZhbHVlcylcbiAgICAgIC50aGVuKCgpID0+ICh7IG9wczogW29iamVjdF0gfSkpXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICBpZiAoZXJyb3IuY29kZSA9PT0gUG9zdGdyZXNVbmlxdWVJbmRleFZpb2xhdGlvbkVycm9yKSB7XG4gICAgICAgICAgY29uc3QgZXJyID0gbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuRFVQTElDQVRFX1ZBTFVFLFxuICAgICAgICAgICAgJ0EgZHVwbGljYXRlIHZhbHVlIGZvciBhIGZpZWxkIHdpdGggdW5pcXVlIHZhbHVlcyB3YXMgcHJvdmlkZWQnXG4gICAgICAgICAgKTtcbiAgICAgICAgICBlcnIudW5kZXJseWluZ0Vycm9yID0gZXJyb3I7XG4gICAgICAgICAgaWYgKGVycm9yLmNvbnN0cmFpbnQpIHtcbiAgICAgICAgICAgIGNvbnN0IG1hdGNoZXMgPSBlcnJvci5jb25zdHJhaW50Lm1hdGNoKC91bmlxdWVfKFthLXpBLVpdKykvKTtcbiAgICAgICAgICAgIGlmIChtYXRjaGVzICYmIEFycmF5LmlzQXJyYXkobWF0Y2hlcykpIHtcbiAgICAgICAgICAgICAgZXJyLnVzZXJJbmZvID0geyBkdXBsaWNhdGVkX2ZpZWxkOiBtYXRjaGVzWzFdIH07XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICAgIGVycm9yID0gZXJyO1xuICAgICAgICB9XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSk7XG4gICAgaWYgKHRyYW5zYWN0aW9uYWxTZXNzaW9uKSB7XG4gICAgICB0cmFuc2FjdGlvbmFsU2Vzc2lvbi5iYXRjaC5wdXNoKHByb21pc2UpO1xuICAgIH1cbiAgICByZXR1cm4gcHJvbWlzZTtcbiAgfVxuXG4gIC8vIFJlbW92ZSBhbGwgb2JqZWN0cyB0aGF0IG1hdGNoIHRoZSBnaXZlbiBQYXJzZSBRdWVyeS5cbiAgLy8gSWYgbm8gb2JqZWN0cyBtYXRjaCwgcmVqZWN0IHdpdGggT0JKRUNUX05PVF9GT1VORC4gSWYgb2JqZWN0cyBhcmUgZm91bmQgYW5kIGRlbGV0ZWQsIHJlc29sdmUgd2l0aCB1bmRlZmluZWQuXG4gIC8vIElmIHRoZXJlIGlzIHNvbWUgb3RoZXIgZXJyb3IsIHJlamVjdCB3aXRoIElOVEVSTkFMX1NFUlZFUl9FUlJPUi5cbiAgYXN5bmMgZGVsZXRlT2JqZWN0c0J5UXVlcnkoXG4gICAgY2xhc3NOYW1lOiBzdHJpbmcsXG4gICAgc2NoZW1hOiBTY2hlbWFUeXBlLFxuICAgIHF1ZXJ5OiBRdWVyeVR5cGUsXG4gICAgdHJhbnNhY3Rpb25hbFNlc3Npb246ID9hbnlcbiAgKSB7XG4gICAgZGVidWcoJ2RlbGV0ZU9iamVjdHNCeVF1ZXJ5Jyk7XG4gICAgY29uc3QgdmFsdWVzID0gW2NsYXNzTmFtZV07XG4gICAgY29uc3QgaW5kZXggPSAyO1xuICAgIGNvbnN0IHdoZXJlID0gYnVpbGRXaGVyZUNsYXVzZSh7XG4gICAgICBzY2hlbWEsXG4gICAgICBpbmRleCxcbiAgICAgIHF1ZXJ5LFxuICAgICAgY2FzZUluc2Vuc2l0aXZlOiBmYWxzZSxcbiAgICB9KTtcbiAgICB2YWx1ZXMucHVzaCguLi53aGVyZS52YWx1ZXMpO1xuICAgIGlmIChPYmplY3Qua2V5cyhxdWVyeSkubGVuZ3RoID09PSAwKSB7XG4gICAgICB3aGVyZS5wYXR0ZXJuID0gJ1RSVUUnO1xuICAgIH1cbiAgICBjb25zdCBxcyA9IGBXSVRIIGRlbGV0ZWQgQVMgKERFTEVURSBGUk9NICQxOm5hbWUgV0hFUkUgJHt3aGVyZS5wYXR0ZXJufSBSRVRVUk5JTkcgKikgU0VMRUNUIGNvdW50KCopIEZST00gZGVsZXRlZGA7XG4gICAgY29uc3QgcHJvbWlzZSA9ICh0cmFuc2FjdGlvbmFsU2Vzc2lvbiA/IHRyYW5zYWN0aW9uYWxTZXNzaW9uLnQgOiB0aGlzLl9jbGllbnQpXG4gICAgICAub25lKHFzLCB2YWx1ZXMsIGEgPT4gK2EuY291bnQpXG4gICAgICAudGhlbihjb3VudCA9PiB7XG4gICAgICAgIGlmIChjb3VudCA9PT0gMCkge1xuICAgICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihQYXJzZS5FcnJvci5PQkpFQ1RfTk9UX0ZPVU5ELCAnT2JqZWN0IG5vdCBmb3VuZC4nKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICByZXR1cm4gY291bnQ7XG4gICAgICAgIH1cbiAgICAgIH0pXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICBpZiAoZXJyb3IuY29kZSAhPT0gUG9zdGdyZXNSZWxhdGlvbkRvZXNOb3RFeGlzdEVycm9yKSB7XG4gICAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICAgIH1cbiAgICAgICAgLy8gRUxTRTogRG9uJ3QgZGVsZXRlIGFueXRoaW5nIGlmIGRvZXNuJ3QgZXhpc3RcbiAgICAgIH0pO1xuICAgIGlmICh0cmFuc2FjdGlvbmFsU2Vzc2lvbikge1xuICAgICAgdHJhbnNhY3Rpb25hbFNlc3Npb24uYmF0Y2gucHVzaChwcm9taXNlKTtcbiAgICB9XG4gICAgcmV0dXJuIHByb21pc2U7XG4gIH1cbiAgLy8gUmV0dXJuIHZhbHVlIG5vdCBjdXJyZW50bHkgd2VsbCBzcGVjaWZpZWQuXG4gIGFzeW5jIGZpbmRPbmVBbmRVcGRhdGUoXG4gICAgY2xhc3NOYW1lOiBzdHJpbmcsXG4gICAgc2NoZW1hOiBTY2hlbWFUeXBlLFxuICAgIHF1ZXJ5OiBRdWVyeVR5cGUsXG4gICAgdXBkYXRlOiBhbnksXG4gICAgdHJhbnNhY3Rpb25hbFNlc3Npb246ID9hbnlcbiAgKTogUHJvbWlzZTxhbnk+IHtcbiAgICBkZWJ1ZygnZmluZE9uZUFuZFVwZGF0ZScpO1xuICAgIHJldHVybiB0aGlzLnVwZGF0ZU9iamVjdHNCeVF1ZXJ5KGNsYXNzTmFtZSwgc2NoZW1hLCBxdWVyeSwgdXBkYXRlLCB0cmFuc2FjdGlvbmFsU2Vzc2lvbikudGhlbihcbiAgICAgIHZhbCA9PiB2YWxbMF1cbiAgICApO1xuICB9XG5cbiAgLy8gQXBwbHkgdGhlIHVwZGF0ZSB0byBhbGwgb2JqZWN0cyB0aGF0IG1hdGNoIHRoZSBnaXZlbiBQYXJzZSBRdWVyeS5cbiAgYXN5bmMgdXBkYXRlT2JqZWN0c0J5UXVlcnkoXG4gICAgY2xhc3NOYW1lOiBzdHJpbmcsXG4gICAgc2NoZW1hOiBTY2hlbWFUeXBlLFxuICAgIHF1ZXJ5OiBRdWVyeVR5cGUsXG4gICAgdXBkYXRlOiBhbnksXG4gICAgdHJhbnNhY3Rpb25hbFNlc3Npb246ID9hbnlcbiAgKTogUHJvbWlzZTxbYW55XT4ge1xuICAgIGRlYnVnKCd1cGRhdGVPYmplY3RzQnlRdWVyeScpO1xuICAgIGNvbnN0IHVwZGF0ZVBhdHRlcm5zID0gW107XG4gICAgY29uc3QgdmFsdWVzID0gW2NsYXNzTmFtZV07XG4gICAgbGV0IGluZGV4ID0gMjtcbiAgICBzY2hlbWEgPSB0b1Bvc3RncmVzU2NoZW1hKHNjaGVtYSk7XG5cbiAgICBjb25zdCBvcmlnaW5hbFVwZGF0ZSA9IHsgLi4udXBkYXRlIH07XG5cbiAgICAvLyBTZXQgZmxhZyBmb3IgZG90IG5vdGF0aW9uIGZpZWxkc1xuICAgIGNvbnN0IGRvdE5vdGF0aW9uT3B0aW9ucyA9IHt9O1xuICAgIE9iamVjdC5rZXlzKHVwZGF0ZSkuZm9yRWFjaChmaWVsZE5hbWUgPT4ge1xuICAgICAgaWYgKGZpZWxkTmFtZS5pbmRleE9mKCcuJykgPiAtMSkge1xuICAgICAgICBjb25zdCBjb21wb25lbnRzID0gZmllbGROYW1lLnNwbGl0KCcuJyk7XG4gICAgICAgIGNvbnN0IGZpcnN0ID0gY29tcG9uZW50cy5zaGlmdCgpO1xuICAgICAgICBkb3ROb3RhdGlvbk9wdGlvbnNbZmlyc3RdID0gdHJ1ZTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGRvdE5vdGF0aW9uT3B0aW9uc1tmaWVsZE5hbWVdID0gZmFsc2U7XG4gICAgICB9XG4gICAgfSk7XG4gICAgdXBkYXRlID0gaGFuZGxlRG90RmllbGRzKHVwZGF0ZSk7XG4gICAgLy8gUmVzb2x2ZSBhdXRoRGF0YSBmaXJzdCxcbiAgICAvLyBTbyB3ZSBkb24ndCBlbmQgdXAgd2l0aCBtdWx0aXBsZSBrZXkgdXBkYXRlc1xuICAgIGZvciAoY29uc3QgZmllbGROYW1lIGluIHVwZGF0ZSkge1xuICAgICAgY29uc3QgYXV0aERhdGFNYXRjaCA9IGZpZWxkTmFtZS5tYXRjaCgvXl9hdXRoX2RhdGFfKFthLXpBLVowLTlfXSspJC8pO1xuICAgICAgaWYgKGF1dGhEYXRhTWF0Y2gpIHtcbiAgICAgICAgdmFyIHByb3ZpZGVyID0gYXV0aERhdGFNYXRjaFsxXTtcbiAgICAgICAgY29uc3QgdmFsdWUgPSB1cGRhdGVbZmllbGROYW1lXTtcbiAgICAgICAgZGVsZXRlIHVwZGF0ZVtmaWVsZE5hbWVdO1xuICAgICAgICB1cGRhdGVbJ2F1dGhEYXRhJ10gPSB1cGRhdGVbJ2F1dGhEYXRhJ10gfHwge307XG4gICAgICAgIHVwZGF0ZVsnYXV0aERhdGEnXVtwcm92aWRlcl0gPSB2YWx1ZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBmb3IgKGNvbnN0IGZpZWxkTmFtZSBpbiB1cGRhdGUpIHtcbiAgICAgIGNvbnN0IGZpZWxkVmFsdWUgPSB1cGRhdGVbZmllbGROYW1lXTtcbiAgICAgIC8vIERyb3AgYW55IHVuZGVmaW5lZCB2YWx1ZXMuXG4gICAgICBpZiAodHlwZW9mIGZpZWxkVmFsdWUgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgIGRlbGV0ZSB1cGRhdGVbZmllbGROYW1lXTtcbiAgICAgIH0gZWxzZSBpZiAoZmllbGRWYWx1ZSA9PT0gbnVsbCkge1xuICAgICAgICB1cGRhdGVQYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9IE5VTExgKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lKTtcbiAgICAgICAgaW5kZXggKz0gMTtcbiAgICAgIH0gZWxzZSBpZiAoZmllbGROYW1lID09ICdhdXRoRGF0YScpIHtcbiAgICAgICAgLy8gVGhpcyByZWN1cnNpdmVseSBzZXRzIHRoZSBqc29uX29iamVjdFxuICAgICAgICAvLyBPbmx5IDEgbGV2ZWwgZGVlcFxuICAgICAgICBjb25zdCBnZW5lcmF0ZSA9IChqc29uYjogc3RyaW5nLCBrZXk6IHN0cmluZywgdmFsdWU6IGFueSkgPT4ge1xuICAgICAgICAgIHJldHVybiBganNvbl9vYmplY3Rfc2V0X2tleShDT0FMRVNDRSgke2pzb25ifSwgJ3t9Jzo6anNvbmIpLCAke2tleX0sICR7dmFsdWV9KTo6anNvbmJgO1xuICAgICAgICB9O1xuICAgICAgICBjb25zdCBsYXN0S2V5ID0gYCQke2luZGV4fTpuYW1lYDtcbiAgICAgICAgY29uc3QgZmllbGROYW1lSW5kZXggPSBpbmRleDtcbiAgICAgICAgaW5kZXggKz0gMTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lKTtcbiAgICAgICAgY29uc3QgdXBkYXRlID0gT2JqZWN0LmtleXMoZmllbGRWYWx1ZSkucmVkdWNlKChsYXN0S2V5OiBzdHJpbmcsIGtleTogc3RyaW5nKSA9PiB7XG4gICAgICAgICAgY29uc3Qgc3RyID0gZ2VuZXJhdGUobGFzdEtleSwgYCQke2luZGV4fTo6dGV4dGAsIGAkJHtpbmRleCArIDF9Ojpqc29uYmApO1xuICAgICAgICAgIGluZGV4ICs9IDI7XG4gICAgICAgICAgbGV0IHZhbHVlID0gZmllbGRWYWx1ZVtrZXldO1xuICAgICAgICAgIGlmICh2YWx1ZSkge1xuICAgICAgICAgICAgaWYgKHZhbHVlLl9fb3AgPT09ICdEZWxldGUnKSB7XG4gICAgICAgICAgICAgIHZhbHVlID0gbnVsbDtcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIHZhbHVlID0gSlNPTi5zdHJpbmdpZnkodmFsdWUpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgICB2YWx1ZXMucHVzaChrZXksIHZhbHVlKTtcbiAgICAgICAgICByZXR1cm4gc3RyO1xuICAgICAgICB9LCBsYXN0S2V5KTtcbiAgICAgICAgdXBkYXRlUGF0dGVybnMucHVzaChgJCR7ZmllbGROYW1lSW5kZXh9Om5hbWUgPSAke3VwZGF0ZX1gKTtcbiAgICAgIH0gZWxzZSBpZiAoZmllbGRWYWx1ZS5fX29wID09PSAnSW5jcmVtZW50Jykge1xuICAgICAgICB1cGRhdGVQYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9IENPQUxFU0NFKCQke2luZGV4fTpuYW1lLCAwKSArICQke2luZGV4ICsgMX1gKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBmaWVsZFZhbHVlLmFtb3VudCk7XG4gICAgICAgIGluZGV4ICs9IDI7XG4gICAgICB9IGVsc2UgaWYgKGZpZWxkVmFsdWUuX19vcCA9PT0gJ0FkZCcpIHtcbiAgICAgICAgdXBkYXRlUGF0dGVybnMucHVzaChcbiAgICAgICAgICBgJCR7aW5kZXh9Om5hbWUgPSBhcnJheV9hZGQoQ09BTEVTQ0UoJCR7aW5kZXh9Om5hbWUsICdbXSc6Ompzb25iKSwgJCR7aW5kZXggKyAxfTo6anNvbmIpYFxuICAgICAgICApO1xuICAgICAgICB2YWx1ZXMucHVzaChmaWVsZE5hbWUsIEpTT04uc3RyaW5naWZ5KGZpZWxkVmFsdWUub2JqZWN0cykpO1xuICAgICAgICBpbmRleCArPSAyO1xuICAgICAgfSBlbHNlIGlmIChmaWVsZFZhbHVlLl9fb3AgPT09ICdEZWxldGUnKSB7XG4gICAgICAgIHVwZGF0ZVBhdHRlcm5zLnB1c2goYCQke2luZGV4fTpuYW1lID0gJCR7aW5kZXggKyAxfWApO1xuICAgICAgICB2YWx1ZXMucHVzaChmaWVsZE5hbWUsIG51bGwpO1xuICAgICAgICBpbmRleCArPSAyO1xuICAgICAgfSBlbHNlIGlmIChmaWVsZFZhbHVlLl9fb3AgPT09ICdSZW1vdmUnKSB7XG4gICAgICAgIHVwZGF0ZVBhdHRlcm5zLnB1c2goXG4gICAgICAgICAgYCQke2luZGV4fTpuYW1lID0gYXJyYXlfcmVtb3ZlKENPQUxFU0NFKCQke2luZGV4fTpuYW1lLCAnW10nOjpqc29uYiksICQke1xuICAgICAgICAgICAgaW5kZXggKyAxXG4gICAgICAgICAgfTo6anNvbmIpYFxuICAgICAgICApO1xuICAgICAgICB2YWx1ZXMucHVzaChmaWVsZE5hbWUsIEpTT04uc3RyaW5naWZ5KGZpZWxkVmFsdWUub2JqZWN0cykpO1xuICAgICAgICBpbmRleCArPSAyO1xuICAgICAgfSBlbHNlIGlmIChmaWVsZFZhbHVlLl9fb3AgPT09ICdBZGRVbmlxdWUnKSB7XG4gICAgICAgIHVwZGF0ZVBhdHRlcm5zLnB1c2goXG4gICAgICAgICAgYCQke2luZGV4fTpuYW1lID0gYXJyYXlfYWRkX3VuaXF1ZShDT0FMRVNDRSgkJHtpbmRleH06bmFtZSwgJ1tdJzo6anNvbmIpLCAkJHtcbiAgICAgICAgICAgIGluZGV4ICsgMVxuICAgICAgICAgIH06Ompzb25iKWBcbiAgICAgICAgKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBKU09OLnN0cmluZ2lmeShmaWVsZFZhbHVlLm9iamVjdHMpKTtcbiAgICAgICAgaW5kZXggKz0gMjtcbiAgICAgIH0gZWxzZSBpZiAoZmllbGROYW1lID09PSAndXBkYXRlZEF0Jykge1xuICAgICAgICAvL1RPRE86IHN0b3Agc3BlY2lhbCBjYXNpbmcgdGhpcy4gSXQgc2hvdWxkIGNoZWNrIGZvciBfX3R5cGUgPT09ICdEYXRlJyBhbmQgdXNlIC5pc29cbiAgICAgICAgdXBkYXRlUGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgPSAkJHtpbmRleCArIDF9YCk7XG4gICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgZmllbGRWYWx1ZSk7XG4gICAgICAgIGluZGV4ICs9IDI7XG4gICAgICB9IGVsc2UgaWYgKHR5cGVvZiBmaWVsZFZhbHVlID09PSAnc3RyaW5nJykge1xuICAgICAgICB1cGRhdGVQYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9ICQke2luZGV4ICsgMX1gKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBmaWVsZFZhbHVlKTtcbiAgICAgICAgaW5kZXggKz0gMjtcbiAgICAgIH0gZWxzZSBpZiAodHlwZW9mIGZpZWxkVmFsdWUgPT09ICdib29sZWFuJykge1xuICAgICAgICB1cGRhdGVQYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9ICQke2luZGV4ICsgMX1gKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBmaWVsZFZhbHVlKTtcbiAgICAgICAgaW5kZXggKz0gMjtcbiAgICAgIH0gZWxzZSBpZiAoZmllbGRWYWx1ZS5fX3R5cGUgPT09ICdQb2ludGVyJykge1xuICAgICAgICB1cGRhdGVQYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9ICQke2luZGV4ICsgMX1gKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBmaWVsZFZhbHVlLm9iamVjdElkKTtcbiAgICAgICAgaW5kZXggKz0gMjtcbiAgICAgIH0gZWxzZSBpZiAoZmllbGRWYWx1ZS5fX3R5cGUgPT09ICdEYXRlJykge1xuICAgICAgICB1cGRhdGVQYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9ICQke2luZGV4ICsgMX1gKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCB0b1Bvc3RncmVzVmFsdWUoZmllbGRWYWx1ZSkpO1xuICAgICAgICBpbmRleCArPSAyO1xuICAgICAgfSBlbHNlIGlmIChmaWVsZFZhbHVlIGluc3RhbmNlb2YgRGF0ZSkge1xuICAgICAgICB1cGRhdGVQYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9ICQke2luZGV4ICsgMX1gKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBmaWVsZFZhbHVlKTtcbiAgICAgICAgaW5kZXggKz0gMjtcbiAgICAgIH0gZWxzZSBpZiAoZmllbGRWYWx1ZS5fX3R5cGUgPT09ICdGaWxlJykge1xuICAgICAgICB1cGRhdGVQYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9ICQke2luZGV4ICsgMX1gKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCB0b1Bvc3RncmVzVmFsdWUoZmllbGRWYWx1ZSkpO1xuICAgICAgICBpbmRleCArPSAyO1xuICAgICAgfSBlbHNlIGlmIChmaWVsZFZhbHVlLl9fdHlwZSA9PT0gJ0dlb1BvaW50Jykge1xuICAgICAgICB1cGRhdGVQYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9IFBPSU5UKCQke2luZGV4ICsgMX0sICQke2luZGV4ICsgMn0pYCk7XG4gICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgZmllbGRWYWx1ZS5sb25naXR1ZGUsIGZpZWxkVmFsdWUubGF0aXR1ZGUpO1xuICAgICAgICBpbmRleCArPSAzO1xuICAgICAgfSBlbHNlIGlmIChmaWVsZFZhbHVlLl9fdHlwZSA9PT0gJ1BvbHlnb24nKSB7XG4gICAgICAgIGNvbnN0IHZhbHVlID0gY29udmVydFBvbHlnb25Ub1NRTChmaWVsZFZhbHVlLmNvb3JkaW5hdGVzKTtcbiAgICAgICAgdXBkYXRlUGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgPSAkJHtpbmRleCArIDF9Ojpwb2x5Z29uYCk7XG4gICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgdmFsdWUpO1xuICAgICAgICBpbmRleCArPSAyO1xuICAgICAgfSBlbHNlIGlmIChmaWVsZFZhbHVlLl9fdHlwZSA9PT0gJ1JlbGF0aW9uJykge1xuICAgICAgICAvLyBub29wXG4gICAgICB9IGVsc2UgaWYgKHR5cGVvZiBmaWVsZFZhbHVlID09PSAnbnVtYmVyJykge1xuICAgICAgICB1cGRhdGVQYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9ICQke2luZGV4ICsgMX1gKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCBmaWVsZFZhbHVlKTtcbiAgICAgICAgaW5kZXggKz0gMjtcbiAgICAgIH0gZWxzZSBpZiAoXG4gICAgICAgIHR5cGVvZiBmaWVsZFZhbHVlID09PSAnb2JqZWN0JyAmJlxuICAgICAgICBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0gJiZcbiAgICAgICAgc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdLnR5cGUgPT09ICdPYmplY3QnXG4gICAgICApIHtcbiAgICAgICAgLy8gR2F0aGVyIGtleXMgdG8gaW5jcmVtZW50XG4gICAgICAgIGNvbnN0IGtleXNUb0luY3JlbWVudCA9IE9iamVjdC5rZXlzKG9yaWdpbmFsVXBkYXRlKVxuICAgICAgICAgIC5maWx0ZXIoayA9PiB7XG4gICAgICAgICAgICAvLyBjaG9vc2UgdG9wIGxldmVsIGZpZWxkcyB0aGF0IGhhdmUgYSBkZWxldGUgb3BlcmF0aW9uIHNldFxuICAgICAgICAgICAgLy8gTm90ZSB0aGF0IE9iamVjdC5rZXlzIGlzIGl0ZXJhdGluZyBvdmVyIHRoZSAqKm9yaWdpbmFsKiogdXBkYXRlIG9iamVjdFxuICAgICAgICAgICAgLy8gYW5kIHRoYXQgc29tZSBvZiB0aGUga2V5cyBvZiB0aGUgb3JpZ2luYWwgdXBkYXRlIGNvdWxkIGJlIG51bGwgb3IgdW5kZWZpbmVkOlxuICAgICAgICAgICAgLy8gKFNlZSB0aGUgYWJvdmUgY2hlY2sgYGlmIChmaWVsZFZhbHVlID09PSBudWxsIHx8IHR5cGVvZiBmaWVsZFZhbHVlID09IFwidW5kZWZpbmVkXCIpYClcbiAgICAgICAgICAgIGNvbnN0IHZhbHVlID0gb3JpZ2luYWxVcGRhdGVba107XG4gICAgICAgICAgICByZXR1cm4gKFxuICAgICAgICAgICAgICB2YWx1ZSAmJlxuICAgICAgICAgICAgICB2YWx1ZS5fX29wID09PSAnSW5jcmVtZW50JyAmJlxuICAgICAgICAgICAgICBrLnNwbGl0KCcuJykubGVuZ3RoID09PSAyICYmXG4gICAgICAgICAgICAgIGsuc3BsaXQoJy4nKVswXSA9PT0gZmllbGROYW1lXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH0pXG4gICAgICAgICAgLm1hcChrID0+IGsuc3BsaXQoJy4nKVsxXSk7XG5cbiAgICAgICAgbGV0IGluY3JlbWVudFBhdHRlcm5zID0gJyc7XG4gICAgICAgIGlmIChrZXlzVG9JbmNyZW1lbnQubGVuZ3RoID4gMCkge1xuICAgICAgICAgIGluY3JlbWVudFBhdHRlcm5zID1cbiAgICAgICAgICAgICcgfHwgJyArXG4gICAgICAgICAgICBrZXlzVG9JbmNyZW1lbnRcbiAgICAgICAgICAgICAgLm1hcChjID0+IHtcbiAgICAgICAgICAgICAgICBjb25zdCBhbW91bnQgPSBmaWVsZFZhbHVlW2NdLmFtb3VudDtcbiAgICAgICAgICAgICAgICByZXR1cm4gYENPTkNBVCgne1wiJHtjfVwiOicsIENPQUxFU0NFKCQke2luZGV4fTpuYW1lLT4+JyR7Y30nLCcwJyk6OmludCArICR7YW1vdW50fSwgJ30nKTo6anNvbmJgO1xuICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAuam9pbignIHx8ICcpO1xuICAgICAgICAgIC8vIFN0cmlwIHRoZSBrZXlzXG4gICAgICAgICAga2V5c1RvSW5jcmVtZW50LmZvckVhY2goa2V5ID0+IHtcbiAgICAgICAgICAgIGRlbGV0ZSBmaWVsZFZhbHVlW2tleV07XG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBrZXlzVG9EZWxldGU6IEFycmF5PHN0cmluZz4gPSBPYmplY3Qua2V5cyhvcmlnaW5hbFVwZGF0ZSlcbiAgICAgICAgICAuZmlsdGVyKGsgPT4ge1xuICAgICAgICAgICAgLy8gY2hvb3NlIHRvcCBsZXZlbCBmaWVsZHMgdGhhdCBoYXZlIGEgZGVsZXRlIG9wZXJhdGlvbiBzZXQuXG4gICAgICAgICAgICBjb25zdCB2YWx1ZSA9IG9yaWdpbmFsVXBkYXRlW2tdO1xuICAgICAgICAgICAgcmV0dXJuIChcbiAgICAgICAgICAgICAgdmFsdWUgJiZcbiAgICAgICAgICAgICAgdmFsdWUuX19vcCA9PT0gJ0RlbGV0ZScgJiZcbiAgICAgICAgICAgICAgay5zcGxpdCgnLicpLmxlbmd0aCA9PT0gMiAmJlxuICAgICAgICAgICAgICBrLnNwbGl0KCcuJylbMF0gPT09IGZpZWxkTmFtZVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9KVxuICAgICAgICAgIC5tYXAoayA9PiBrLnNwbGl0KCcuJylbMV0pO1xuXG4gICAgICAgIGNvbnN0IGRlbGV0ZVBhdHRlcm5zID0ga2V5c1RvRGVsZXRlLnJlZHVjZSgocDogc3RyaW5nLCBjOiBzdHJpbmcsIGk6IG51bWJlcikgPT4ge1xuICAgICAgICAgIHJldHVybiBwICsgYCAtICckJHtpbmRleCArIDEgKyBpfTp2YWx1ZSdgO1xuICAgICAgICB9LCAnJyk7XG4gICAgICAgIC8vIE92ZXJyaWRlIE9iamVjdFxuICAgICAgICBsZXQgdXBkYXRlT2JqZWN0ID0gXCIne30nOjpqc29uYlwiO1xuXG4gICAgICAgIGlmIChkb3ROb3RhdGlvbk9wdGlvbnNbZmllbGROYW1lXSkge1xuICAgICAgICAgIC8vIE1lcmdlIE9iamVjdFxuICAgICAgICAgIHVwZGF0ZU9iamVjdCA9IGBDT0FMRVNDRSgkJHtpbmRleH06bmFtZSwgJ3t9Jzo6anNvbmIpYDtcbiAgICAgICAgfVxuICAgICAgICB1cGRhdGVQYXR0ZXJucy5wdXNoKFxuICAgICAgICAgIGAkJHtpbmRleH06bmFtZSA9ICgke3VwZGF0ZU9iamVjdH0gJHtkZWxldGVQYXR0ZXJuc30gJHtpbmNyZW1lbnRQYXR0ZXJuc30gfHwgJCR7XG4gICAgICAgICAgICBpbmRleCArIDEgKyBrZXlzVG9EZWxldGUubGVuZ3RoXG4gICAgICAgICAgfTo6anNvbmIgKWBcbiAgICAgICAgKTtcbiAgICAgICAgdmFsdWVzLnB1c2goZmllbGROYW1lLCAuLi5rZXlzVG9EZWxldGUsIEpTT04uc3RyaW5naWZ5KGZpZWxkVmFsdWUpKTtcbiAgICAgICAgaW5kZXggKz0gMiArIGtleXNUb0RlbGV0ZS5sZW5ndGg7XG4gICAgICB9IGVsc2UgaWYgKFxuICAgICAgICBBcnJheS5pc0FycmF5KGZpZWxkVmFsdWUpICYmXG4gICAgICAgIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXSAmJlxuICAgICAgICBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0udHlwZSA9PT0gJ0FycmF5J1xuICAgICAgKSB7XG4gICAgICAgIGNvbnN0IGV4cGVjdGVkVHlwZSA9IHBhcnNlVHlwZVRvUG9zdGdyZXNUeXBlKHNjaGVtYS5maWVsZHNbZmllbGROYW1lXSk7XG4gICAgICAgIGlmIChleHBlY3RlZFR5cGUgPT09ICd0ZXh0W10nKSB7XG4gICAgICAgICAgdXBkYXRlUGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgPSAkJHtpbmRleCArIDF9Ojp0ZXh0W11gKTtcbiAgICAgICAgICB2YWx1ZXMucHVzaChmaWVsZE5hbWUsIGZpZWxkVmFsdWUpO1xuICAgICAgICAgIGluZGV4ICs9IDI7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdXBkYXRlUGF0dGVybnMucHVzaChgJCR7aW5kZXh9Om5hbWUgPSAkJHtpbmRleCArIDF9Ojpqc29uYmApO1xuICAgICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkTmFtZSwgSlNPTi5zdHJpbmdpZnkoZmllbGRWYWx1ZSkpO1xuICAgICAgICAgIGluZGV4ICs9IDI7XG4gICAgICAgIH1cbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGRlYnVnKCdOb3Qgc3VwcG9ydGVkIHVwZGF0ZScsIHsgZmllbGROYW1lLCBmaWVsZFZhbHVlIH0pO1xuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoXG4gICAgICAgICAgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgICAgICAgUGFyc2UuRXJyb3IuT1BFUkFUSU9OX0ZPUkJJRERFTixcbiAgICAgICAgICAgIGBQb3N0Z3JlcyBkb2Vzbid0IHN1cHBvcnQgdXBkYXRlICR7SlNPTi5zdHJpbmdpZnkoZmllbGRWYWx1ZSl9IHlldGBcbiAgICAgICAgICApXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgY29uc3Qgd2hlcmUgPSBidWlsZFdoZXJlQ2xhdXNlKHtcbiAgICAgIHNjaGVtYSxcbiAgICAgIGluZGV4LFxuICAgICAgcXVlcnksXG4gICAgICBjYXNlSW5zZW5zaXRpdmU6IGZhbHNlLFxuICAgIH0pO1xuICAgIHZhbHVlcy5wdXNoKC4uLndoZXJlLnZhbHVlcyk7XG5cbiAgICBjb25zdCB3aGVyZUNsYXVzZSA9IHdoZXJlLnBhdHRlcm4ubGVuZ3RoID4gMCA/IGBXSEVSRSAke3doZXJlLnBhdHRlcm59YCA6ICcnO1xuICAgIGNvbnN0IHFzID0gYFVQREFURSAkMTpuYW1lIFNFVCAke3VwZGF0ZVBhdHRlcm5zLmpvaW4oKX0gJHt3aGVyZUNsYXVzZX0gUkVUVVJOSU5HICpgO1xuICAgIGNvbnN0IHByb21pc2UgPSAodHJhbnNhY3Rpb25hbFNlc3Npb24gPyB0cmFuc2FjdGlvbmFsU2Vzc2lvbi50IDogdGhpcy5fY2xpZW50KS5hbnkocXMsIHZhbHVlcyk7XG4gICAgaWYgKHRyYW5zYWN0aW9uYWxTZXNzaW9uKSB7XG4gICAgICB0cmFuc2FjdGlvbmFsU2Vzc2lvbi5iYXRjaC5wdXNoKHByb21pc2UpO1xuICAgIH1cbiAgICByZXR1cm4gcHJvbWlzZTtcbiAgfVxuXG4gIC8vIEhvcGVmdWxseSwgd2UgY2FuIGdldCByaWQgb2YgdGhpcy4gSXQncyBvbmx5IHVzZWQgZm9yIGNvbmZpZyBhbmQgaG9va3MuXG4gIHVwc2VydE9uZU9iamVjdChcbiAgICBjbGFzc05hbWU6IHN0cmluZyxcbiAgICBzY2hlbWE6IFNjaGVtYVR5cGUsXG4gICAgcXVlcnk6IFF1ZXJ5VHlwZSxcbiAgICB1cGRhdGU6IGFueSxcbiAgICB0cmFuc2FjdGlvbmFsU2Vzc2lvbjogP2FueVxuICApIHtcbiAgICBkZWJ1ZygndXBzZXJ0T25lT2JqZWN0Jyk7XG4gICAgY29uc3QgY3JlYXRlVmFsdWUgPSBPYmplY3QuYXNzaWduKHt9LCBxdWVyeSwgdXBkYXRlKTtcbiAgICByZXR1cm4gdGhpcy5jcmVhdGVPYmplY3QoY2xhc3NOYW1lLCBzY2hlbWEsIGNyZWF0ZVZhbHVlLCB0cmFuc2FjdGlvbmFsU2Vzc2lvbikuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgLy8gaWdub3JlIGR1cGxpY2F0ZSB2YWx1ZSBlcnJvcnMgYXMgaXQncyB1cHNlcnRcbiAgICAgIGlmIChlcnJvci5jb2RlICE9PSBQYXJzZS5FcnJvci5EVVBMSUNBVEVfVkFMVUUpIHtcbiAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICB9XG4gICAgICByZXR1cm4gdGhpcy5maW5kT25lQW5kVXBkYXRlKGNsYXNzTmFtZSwgc2NoZW1hLCBxdWVyeSwgdXBkYXRlLCB0cmFuc2FjdGlvbmFsU2Vzc2lvbik7XG4gICAgfSk7XG4gIH1cblxuICBmaW5kKFxuICAgIGNsYXNzTmFtZTogc3RyaW5nLFxuICAgIHNjaGVtYTogU2NoZW1hVHlwZSxcbiAgICBxdWVyeTogUXVlcnlUeXBlLFxuICAgIHsgc2tpcCwgbGltaXQsIHNvcnQsIGtleXMsIGNhc2VJbnNlbnNpdGl2ZSwgZXhwbGFpbiB9OiBRdWVyeU9wdGlvbnNcbiAgKSB7XG4gICAgZGVidWcoJ2ZpbmQnKTtcbiAgICBjb25zdCBoYXNMaW1pdCA9IGxpbWl0ICE9PSB1bmRlZmluZWQ7XG4gICAgY29uc3QgaGFzU2tpcCA9IHNraXAgIT09IHVuZGVmaW5lZDtcbiAgICBsZXQgdmFsdWVzID0gW2NsYXNzTmFtZV07XG4gICAgY29uc3Qgd2hlcmUgPSBidWlsZFdoZXJlQ2xhdXNlKHtcbiAgICAgIHNjaGVtYSxcbiAgICAgIHF1ZXJ5LFxuICAgICAgaW5kZXg6IDIsXG4gICAgICBjYXNlSW5zZW5zaXRpdmUsXG4gICAgfSk7XG4gICAgdmFsdWVzLnB1c2goLi4ud2hlcmUudmFsdWVzKTtcblxuICAgIGNvbnN0IHdoZXJlUGF0dGVybiA9IHdoZXJlLnBhdHRlcm4ubGVuZ3RoID4gMCA/IGBXSEVSRSAke3doZXJlLnBhdHRlcm59YCA6ICcnO1xuICAgIGNvbnN0IGxpbWl0UGF0dGVybiA9IGhhc0xpbWl0ID8gYExJTUlUICQke3ZhbHVlcy5sZW5ndGggKyAxfWAgOiAnJztcbiAgICBpZiAoaGFzTGltaXQpIHtcbiAgICAgIHZhbHVlcy5wdXNoKGxpbWl0KTtcbiAgICB9XG4gICAgY29uc3Qgc2tpcFBhdHRlcm4gPSBoYXNTa2lwID8gYE9GRlNFVCAkJHt2YWx1ZXMubGVuZ3RoICsgMX1gIDogJyc7XG4gICAgaWYgKGhhc1NraXApIHtcbiAgICAgIHZhbHVlcy5wdXNoKHNraXApO1xuICAgIH1cblxuICAgIGxldCBzb3J0UGF0dGVybiA9ICcnO1xuICAgIGlmIChzb3J0KSB7XG4gICAgICBjb25zdCBzb3J0Q29weTogYW55ID0gc29ydDtcbiAgICAgIGNvbnN0IHNvcnRpbmcgPSBPYmplY3Qua2V5cyhzb3J0KVxuICAgICAgICAubWFwKGtleSA9PiB7XG4gICAgICAgICAgY29uc3QgdHJhbnNmb3JtS2V5ID0gdHJhbnNmb3JtRG90RmllbGRUb0NvbXBvbmVudHMoa2V5KS5qb2luKCctPicpO1xuICAgICAgICAgIC8vIFVzaW5nICRpZHggcGF0dGVybiBnaXZlczogIG5vbi1pbnRlZ2VyIGNvbnN0YW50IGluIE9SREVSIEJZXG4gICAgICAgICAgaWYgKHNvcnRDb3B5W2tleV0gPT09IDEpIHtcbiAgICAgICAgICAgIHJldHVybiBgJHt0cmFuc2Zvcm1LZXl9IEFTQ2A7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybiBgJHt0cmFuc2Zvcm1LZXl9IERFU0NgO1xuICAgICAgICB9KVxuICAgICAgICAuam9pbigpO1xuICAgICAgc29ydFBhdHRlcm4gPSBzb3J0ICE9PSB1bmRlZmluZWQgJiYgT2JqZWN0LmtleXMoc29ydCkubGVuZ3RoID4gMCA/IGBPUkRFUiBCWSAke3NvcnRpbmd9YCA6ICcnO1xuICAgIH1cbiAgICBpZiAod2hlcmUuc29ydHMgJiYgT2JqZWN0LmtleXMoKHdoZXJlLnNvcnRzOiBhbnkpKS5sZW5ndGggPiAwKSB7XG4gICAgICBzb3J0UGF0dGVybiA9IGBPUkRFUiBCWSAke3doZXJlLnNvcnRzLmpvaW4oKX1gO1xuICAgIH1cblxuICAgIGxldCBjb2x1bW5zID0gJyonO1xuICAgIGlmIChrZXlzKSB7XG4gICAgICAvLyBFeGNsdWRlIGVtcHR5IGtleXNcbiAgICAgIC8vIFJlcGxhY2UgQUNMIGJ5IGl0J3Mga2V5c1xuICAgICAga2V5cyA9IGtleXMucmVkdWNlKChtZW1vLCBrZXkpID0+IHtcbiAgICAgICAgaWYgKGtleSA9PT0gJ0FDTCcpIHtcbiAgICAgICAgICBtZW1vLnB1c2goJ19ycGVybScpO1xuICAgICAgICAgIG1lbW8ucHVzaCgnX3dwZXJtJyk7XG4gICAgICAgIH0gZWxzZSBpZiAoa2V5Lmxlbmd0aCA+IDApIHtcbiAgICAgICAgICBtZW1vLnB1c2goa2V5KTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gbWVtbztcbiAgICAgIH0sIFtdKTtcbiAgICAgIGNvbHVtbnMgPSBrZXlzXG4gICAgICAgIC5tYXAoKGtleSwgaW5kZXgpID0+IHtcbiAgICAgICAgICBpZiAoa2V5ID09PSAnJHNjb3JlJykge1xuICAgICAgICAgICAgcmV0dXJuIGB0c19yYW5rX2NkKHRvX3RzdmVjdG9yKCQkezJ9LCAkJHszfTpuYW1lKSwgdG9fdHNxdWVyeSgkJHs0fSwgJCR7NX0pLCAzMikgYXMgc2NvcmVgO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gYCQke2luZGV4ICsgdmFsdWVzLmxlbmd0aCArIDF9Om5hbWVgO1xuICAgICAgICB9KVxuICAgICAgICAuam9pbigpO1xuICAgICAgdmFsdWVzID0gdmFsdWVzLmNvbmNhdChrZXlzKTtcbiAgICB9XG5cbiAgICBjb25zdCBvcmlnaW5hbFF1ZXJ5ID0gYFNFTEVDVCAke2NvbHVtbnN9IEZST00gJDE6bmFtZSAke3doZXJlUGF0dGVybn0gJHtzb3J0UGF0dGVybn0gJHtsaW1pdFBhdHRlcm59ICR7c2tpcFBhdHRlcm59YDtcbiAgICBjb25zdCBxcyA9IGV4cGxhaW4gPyB0aGlzLmNyZWF0ZUV4cGxhaW5hYmxlUXVlcnkob3JpZ2luYWxRdWVyeSkgOiBvcmlnaW5hbFF1ZXJ5O1xuICAgIHJldHVybiB0aGlzLl9jbGllbnRcbiAgICAgIC5hbnkocXMsIHZhbHVlcylcbiAgICAgIC5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgIC8vIFF1ZXJ5IG9uIG5vbiBleGlzdGluZyB0YWJsZSwgZG9uJ3QgY3Jhc2hcbiAgICAgICAgaWYgKGVycm9yLmNvZGUgIT09IFBvc3RncmVzUmVsYXRpb25Eb2VzTm90RXhpc3RFcnJvcikge1xuICAgICAgICAgIHRocm93IGVycm9yO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBbXTtcbiAgICAgIH0pXG4gICAgICAudGhlbihyZXN1bHRzID0+IHtcbiAgICAgICAgaWYgKGV4cGxhaW4pIHtcbiAgICAgICAgICByZXR1cm4gcmVzdWx0cztcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gcmVzdWx0cy5tYXAob2JqZWN0ID0+IHRoaXMucG9zdGdyZXNPYmplY3RUb1BhcnNlT2JqZWN0KGNsYXNzTmFtZSwgb2JqZWN0LCBzY2hlbWEpKTtcbiAgICAgIH0pO1xuICB9XG5cbiAgLy8gQ29udmVydHMgZnJvbSBhIHBvc3RncmVzLWZvcm1hdCBvYmplY3QgdG8gYSBSRVNULWZvcm1hdCBvYmplY3QuXG4gIC8vIERvZXMgbm90IHN0cmlwIG91dCBhbnl0aGluZyBiYXNlZCBvbiBhIGxhY2sgb2YgYXV0aGVudGljYXRpb24uXG4gIHBvc3RncmVzT2JqZWN0VG9QYXJzZU9iamVjdChjbGFzc05hbWU6IHN0cmluZywgb2JqZWN0OiBhbnksIHNjaGVtYTogYW55KSB7XG4gICAgT2JqZWN0LmtleXMoc2NoZW1hLmZpZWxkcykuZm9yRWFjaChmaWVsZE5hbWUgPT4ge1xuICAgICAgaWYgKHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS50eXBlID09PSAnUG9pbnRlcicgJiYgb2JqZWN0W2ZpZWxkTmFtZV0pIHtcbiAgICAgICAgb2JqZWN0W2ZpZWxkTmFtZV0gPSB7XG4gICAgICAgICAgb2JqZWN0SWQ6IG9iamVjdFtmaWVsZE5hbWVdLFxuICAgICAgICAgIF9fdHlwZTogJ1BvaW50ZXInLFxuICAgICAgICAgIGNsYXNzTmFtZTogc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdLnRhcmdldENsYXNzLFxuICAgICAgICB9O1xuICAgICAgfVxuICAgICAgaWYgKHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS50eXBlID09PSAnUmVsYXRpb24nKSB7XG4gICAgICAgIG9iamVjdFtmaWVsZE5hbWVdID0ge1xuICAgICAgICAgIF9fdHlwZTogJ1JlbGF0aW9uJyxcbiAgICAgICAgICBjbGFzc05hbWU6IHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS50YXJnZXRDbGFzcyxcbiAgICAgICAgfTtcbiAgICAgIH1cbiAgICAgIGlmIChvYmplY3RbZmllbGROYW1lXSAmJiBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0udHlwZSA9PT0gJ0dlb1BvaW50Jykge1xuICAgICAgICBvYmplY3RbZmllbGROYW1lXSA9IHtcbiAgICAgICAgICBfX3R5cGU6ICdHZW9Qb2ludCcsXG4gICAgICAgICAgbGF0aXR1ZGU6IG9iamVjdFtmaWVsZE5hbWVdLnksXG4gICAgICAgICAgbG9uZ2l0dWRlOiBvYmplY3RbZmllbGROYW1lXS54LFxuICAgICAgICB9O1xuICAgICAgfVxuICAgICAgaWYgKG9iamVjdFtmaWVsZE5hbWVdICYmIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS50eXBlID09PSAnUG9seWdvbicpIHtcbiAgICAgICAgbGV0IGNvb3JkcyA9IG9iamVjdFtmaWVsZE5hbWVdO1xuICAgICAgICBjb29yZHMgPSBjb29yZHMuc3Vic3RyKDIsIGNvb3Jkcy5sZW5ndGggLSA0KS5zcGxpdCgnKSwoJyk7XG4gICAgICAgIGNvb3JkcyA9IGNvb3Jkcy5tYXAocG9pbnQgPT4ge1xuICAgICAgICAgIHJldHVybiBbcGFyc2VGbG9hdChwb2ludC5zcGxpdCgnLCcpWzFdKSwgcGFyc2VGbG9hdChwb2ludC5zcGxpdCgnLCcpWzBdKV07XG4gICAgICAgIH0pO1xuICAgICAgICBvYmplY3RbZmllbGROYW1lXSA9IHtcbiAgICAgICAgICBfX3R5cGU6ICdQb2x5Z29uJyxcbiAgICAgICAgICBjb29yZGluYXRlczogY29vcmRzLFxuICAgICAgICB9O1xuICAgICAgfVxuICAgICAgaWYgKG9iamVjdFtmaWVsZE5hbWVdICYmIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS50eXBlID09PSAnRmlsZScpIHtcbiAgICAgICAgb2JqZWN0W2ZpZWxkTmFtZV0gPSB7XG4gICAgICAgICAgX190eXBlOiAnRmlsZScsXG4gICAgICAgICAgbmFtZTogb2JqZWN0W2ZpZWxkTmFtZV0sXG4gICAgICAgIH07XG4gICAgICB9XG4gICAgfSk7XG4gICAgLy9UT0RPOiByZW1vdmUgdGhpcyByZWxpYW5jZSBvbiB0aGUgbW9uZ28gZm9ybWF0LiBEQiBhZGFwdGVyIHNob3VsZG4ndCBrbm93IHRoZXJlIGlzIGEgZGlmZmVyZW5jZSBiZXR3ZWVuIGNyZWF0ZWQgYXQgYW5kIGFueSBvdGhlciBkYXRlIGZpZWxkLlxuICAgIGlmIChvYmplY3QuY3JlYXRlZEF0KSB7XG4gICAgICBvYmplY3QuY3JlYXRlZEF0ID0gb2JqZWN0LmNyZWF0ZWRBdC50b0lTT1N0cmluZygpO1xuICAgIH1cbiAgICBpZiAob2JqZWN0LnVwZGF0ZWRBdCkge1xuICAgICAgb2JqZWN0LnVwZGF0ZWRBdCA9IG9iamVjdC51cGRhdGVkQXQudG9JU09TdHJpbmcoKTtcbiAgICB9XG4gICAgaWYgKG9iamVjdC5leHBpcmVzQXQpIHtcbiAgICAgIG9iamVjdC5leHBpcmVzQXQgPSB7XG4gICAgICAgIF9fdHlwZTogJ0RhdGUnLFxuICAgICAgICBpc286IG9iamVjdC5leHBpcmVzQXQudG9JU09TdHJpbmcoKSxcbiAgICAgIH07XG4gICAgfVxuICAgIGlmIChvYmplY3QuX2VtYWlsX3ZlcmlmeV90b2tlbl9leHBpcmVzX2F0KSB7XG4gICAgICBvYmplY3QuX2VtYWlsX3ZlcmlmeV90b2tlbl9leHBpcmVzX2F0ID0ge1xuICAgICAgICBfX3R5cGU6ICdEYXRlJyxcbiAgICAgICAgaXNvOiBvYmplY3QuX2VtYWlsX3ZlcmlmeV90b2tlbl9leHBpcmVzX2F0LnRvSVNPU3RyaW5nKCksXG4gICAgICB9O1xuICAgIH1cbiAgICBpZiAob2JqZWN0Ll9hY2NvdW50X2xvY2tvdXRfZXhwaXJlc19hdCkge1xuICAgICAgb2JqZWN0Ll9hY2NvdW50X2xvY2tvdXRfZXhwaXJlc19hdCA9IHtcbiAgICAgICAgX190eXBlOiAnRGF0ZScsXG4gICAgICAgIGlzbzogb2JqZWN0Ll9hY2NvdW50X2xvY2tvdXRfZXhwaXJlc19hdC50b0lTT1N0cmluZygpLFxuICAgICAgfTtcbiAgICB9XG4gICAgaWYgKG9iamVjdC5fcGVyaXNoYWJsZV90b2tlbl9leHBpcmVzX2F0KSB7XG4gICAgICBvYmplY3QuX3BlcmlzaGFibGVfdG9rZW5fZXhwaXJlc19hdCA9IHtcbiAgICAgICAgX190eXBlOiAnRGF0ZScsXG4gICAgICAgIGlzbzogb2JqZWN0Ll9wZXJpc2hhYmxlX3Rva2VuX2V4cGlyZXNfYXQudG9JU09TdHJpbmcoKSxcbiAgICAgIH07XG4gICAgfVxuICAgIGlmIChvYmplY3QuX3Bhc3N3b3JkX2NoYW5nZWRfYXQpIHtcbiAgICAgIG9iamVjdC5fcGFzc3dvcmRfY2hhbmdlZF9hdCA9IHtcbiAgICAgICAgX190eXBlOiAnRGF0ZScsXG4gICAgICAgIGlzbzogb2JqZWN0Ll9wYXNzd29yZF9jaGFuZ2VkX2F0LnRvSVNPU3RyaW5nKCksXG4gICAgICB9O1xuICAgIH1cblxuICAgIGZvciAoY29uc3QgZmllbGROYW1lIGluIG9iamVjdCkge1xuICAgICAgaWYgKG9iamVjdFtmaWVsZE5hbWVdID09PSBudWxsKSB7XG4gICAgICAgIGRlbGV0ZSBvYmplY3RbZmllbGROYW1lXTtcbiAgICAgIH1cbiAgICAgIGlmIChvYmplY3RbZmllbGROYW1lXSBpbnN0YW5jZW9mIERhdGUpIHtcbiAgICAgICAgb2JqZWN0W2ZpZWxkTmFtZV0gPSB7XG4gICAgICAgICAgX190eXBlOiAnRGF0ZScsXG4gICAgICAgICAgaXNvOiBvYmplY3RbZmllbGROYW1lXS50b0lTT1N0cmluZygpLFxuICAgICAgICB9O1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiBvYmplY3Q7XG4gIH1cblxuICAvLyBDcmVhdGUgYSB1bmlxdWUgaW5kZXguIFVuaXF1ZSBpbmRleGVzIG9uIG51bGxhYmxlIGZpZWxkcyBhcmUgbm90IGFsbG93ZWQuIFNpbmNlIHdlIGRvbid0XG4gIC8vIGN1cnJlbnRseSBrbm93IHdoaWNoIGZpZWxkcyBhcmUgbnVsbGFibGUgYW5kIHdoaWNoIGFyZW4ndCwgd2UgaWdub3JlIHRoYXQgY3JpdGVyaWEuXG4gIC8vIEFzIHN1Y2gsIHdlIHNob3VsZG4ndCBleHBvc2UgdGhpcyBmdW5jdGlvbiB0byB1c2VycyBvZiBwYXJzZSB1bnRpbCB3ZSBoYXZlIGFuIG91dC1vZi1iYW5kXG4gIC8vIFdheSBvZiBkZXRlcm1pbmluZyBpZiBhIGZpZWxkIGlzIG51bGxhYmxlLiBVbmRlZmluZWQgZG9lc24ndCBjb3VudCBhZ2FpbnN0IHVuaXF1ZW5lc3MsXG4gIC8vIHdoaWNoIGlzIHdoeSB3ZSB1c2Ugc3BhcnNlIGluZGV4ZXMuXG4gIGFzeW5jIGVuc3VyZVVuaXF1ZW5lc3MoY2xhc3NOYW1lOiBzdHJpbmcsIHNjaGVtYTogU2NoZW1hVHlwZSwgZmllbGROYW1lczogc3RyaW5nW10pIHtcbiAgICBjb25zdCBjb25zdHJhaW50TmFtZSA9IGAke2NsYXNzTmFtZX1fdW5pcXVlXyR7ZmllbGROYW1lcy5zb3J0KCkuam9pbignXycpfWA7XG4gICAgY29uc3QgY29uc3RyYWludFBhdHRlcm5zID0gZmllbGROYW1lcy5tYXAoKGZpZWxkTmFtZSwgaW5kZXgpID0+IGAkJHtpbmRleCArIDN9Om5hbWVgKTtcbiAgICBjb25zdCBxcyA9IGBDUkVBVEUgVU5JUVVFIElOREVYIElGIE5PVCBFWElTVFMgJDI6bmFtZSBPTiAkMTpuYW1lKCR7Y29uc3RyYWludFBhdHRlcm5zLmpvaW4oKX0pYDtcbiAgICByZXR1cm4gdGhpcy5fY2xpZW50Lm5vbmUocXMsIFtjbGFzc05hbWUsIGNvbnN0cmFpbnROYW1lLCAuLi5maWVsZE5hbWVzXSkuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgaWYgKGVycm9yLmNvZGUgPT09IFBvc3RncmVzRHVwbGljYXRlUmVsYXRpb25FcnJvciAmJiBlcnJvci5tZXNzYWdlLmluY2x1ZGVzKGNvbnN0cmFpbnROYW1lKSkge1xuICAgICAgICAvLyBJbmRleCBhbHJlYWR5IGV4aXN0cy4gSWdub3JlIGVycm9yLlxuICAgICAgfSBlbHNlIGlmIChcbiAgICAgICAgZXJyb3IuY29kZSA9PT0gUG9zdGdyZXNVbmlxdWVJbmRleFZpb2xhdGlvbkVycm9yICYmXG4gICAgICAgIGVycm9yLm1lc3NhZ2UuaW5jbHVkZXMoY29uc3RyYWludE5hbWUpXG4gICAgICApIHtcbiAgICAgICAgLy8gQ2FzdCB0aGUgZXJyb3IgaW50byB0aGUgcHJvcGVyIHBhcnNlIGVycm9yXG4gICAgICAgIHRocm93IG5ldyBQYXJzZS5FcnJvcihcbiAgICAgICAgICBQYXJzZS5FcnJvci5EVVBMSUNBVEVfVkFMVUUsXG4gICAgICAgICAgJ0EgZHVwbGljYXRlIHZhbHVlIGZvciBhIGZpZWxkIHdpdGggdW5pcXVlIHZhbHVlcyB3YXMgcHJvdmlkZWQnXG4gICAgICAgICk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIC8vIEV4ZWN1dGVzIGEgY291bnQuXG4gIGFzeW5jIGNvdW50KFxuICAgIGNsYXNzTmFtZTogc3RyaW5nLFxuICAgIHNjaGVtYTogU2NoZW1hVHlwZSxcbiAgICBxdWVyeTogUXVlcnlUeXBlLFxuICAgIHJlYWRQcmVmZXJlbmNlPzogc3RyaW5nLFxuICAgIGVzdGltYXRlPzogYm9vbGVhbiA9IHRydWVcbiAgKSB7XG4gICAgZGVidWcoJ2NvdW50Jyk7XG4gICAgY29uc3QgdmFsdWVzID0gW2NsYXNzTmFtZV07XG4gICAgY29uc3Qgd2hlcmUgPSBidWlsZFdoZXJlQ2xhdXNlKHtcbiAgICAgIHNjaGVtYSxcbiAgICAgIHF1ZXJ5LFxuICAgICAgaW5kZXg6IDIsXG4gICAgICBjYXNlSW5zZW5zaXRpdmU6IGZhbHNlLFxuICAgIH0pO1xuICAgIHZhbHVlcy5wdXNoKC4uLndoZXJlLnZhbHVlcyk7XG5cbiAgICBjb25zdCB3aGVyZVBhdHRlcm4gPSB3aGVyZS5wYXR0ZXJuLmxlbmd0aCA+IDAgPyBgV0hFUkUgJHt3aGVyZS5wYXR0ZXJufWAgOiAnJztcbiAgICBsZXQgcXMgPSAnJztcblxuICAgIGlmICh3aGVyZS5wYXR0ZXJuLmxlbmd0aCA+IDAgfHwgIWVzdGltYXRlKSB7XG4gICAgICBxcyA9IGBTRUxFQ1QgY291bnQoKikgRlJPTSAkMTpuYW1lICR7d2hlcmVQYXR0ZXJufWA7XG4gICAgfSBlbHNlIHtcbiAgICAgIHFzID0gJ1NFTEVDVCByZWx0dXBsZXMgQVMgYXBwcm94aW1hdGVfcm93X2NvdW50IEZST00gcGdfY2xhc3MgV0hFUkUgcmVsbmFtZSA9ICQxJztcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5fY2xpZW50XG4gICAgICAub25lKHFzLCB2YWx1ZXMsIGEgPT4ge1xuICAgICAgICBpZiAoYS5hcHByb3hpbWF0ZV9yb3dfY291bnQgIT0gbnVsbCkge1xuICAgICAgICAgIHJldHVybiArYS5hcHByb3hpbWF0ZV9yb3dfY291bnQ7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcmV0dXJuICthLmNvdW50O1xuICAgICAgICB9XG4gICAgICB9KVxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgaWYgKGVycm9yLmNvZGUgIT09IFBvc3RncmVzUmVsYXRpb25Eb2VzTm90RXhpc3RFcnJvcikge1xuICAgICAgICAgIHRocm93IGVycm9yO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiAwO1xuICAgICAgfSk7XG4gIH1cblxuICBhc3luYyBkaXN0aW5jdChjbGFzc05hbWU6IHN0cmluZywgc2NoZW1hOiBTY2hlbWFUeXBlLCBxdWVyeTogUXVlcnlUeXBlLCBmaWVsZE5hbWU6IHN0cmluZykge1xuICAgIGRlYnVnKCdkaXN0aW5jdCcpO1xuICAgIGxldCBmaWVsZCA9IGZpZWxkTmFtZTtcbiAgICBsZXQgY29sdW1uID0gZmllbGROYW1lO1xuICAgIGNvbnN0IGlzTmVzdGVkID0gZmllbGROYW1lLmluZGV4T2YoJy4nKSA+PSAwO1xuICAgIGlmIChpc05lc3RlZCkge1xuICAgICAgZmllbGQgPSB0cmFuc2Zvcm1Eb3RGaWVsZFRvQ29tcG9uZW50cyhmaWVsZE5hbWUpLmpvaW4oJy0+Jyk7XG4gICAgICBjb2x1bW4gPSBmaWVsZE5hbWUuc3BsaXQoJy4nKVswXTtcbiAgICB9XG4gICAgY29uc3QgaXNBcnJheUZpZWxkID1cbiAgICAgIHNjaGVtYS5maWVsZHMgJiYgc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdICYmIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS50eXBlID09PSAnQXJyYXknO1xuICAgIGNvbnN0IGlzUG9pbnRlckZpZWxkID1cbiAgICAgIHNjaGVtYS5maWVsZHMgJiYgc2NoZW1hLmZpZWxkc1tmaWVsZE5hbWVdICYmIHNjaGVtYS5maWVsZHNbZmllbGROYW1lXS50eXBlID09PSAnUG9pbnRlcic7XG4gICAgY29uc3QgdmFsdWVzID0gW2ZpZWxkLCBjb2x1bW4sIGNsYXNzTmFtZV07XG4gICAgY29uc3Qgd2hlcmUgPSBidWlsZFdoZXJlQ2xhdXNlKHtcbiAgICAgIHNjaGVtYSxcbiAgICAgIHF1ZXJ5LFxuICAgICAgaW5kZXg6IDQsXG4gICAgICBjYXNlSW5zZW5zaXRpdmU6IGZhbHNlLFxuICAgIH0pO1xuICAgIHZhbHVlcy5wdXNoKC4uLndoZXJlLnZhbHVlcyk7XG5cbiAgICBjb25zdCB3aGVyZVBhdHRlcm4gPSB3aGVyZS5wYXR0ZXJuLmxlbmd0aCA+IDAgPyBgV0hFUkUgJHt3aGVyZS5wYXR0ZXJufWAgOiAnJztcbiAgICBjb25zdCB0cmFuc2Zvcm1lciA9IGlzQXJyYXlGaWVsZCA/ICdqc29uYl9hcnJheV9lbGVtZW50cycgOiAnT04nO1xuICAgIGxldCBxcyA9IGBTRUxFQ1QgRElTVElOQ1QgJHt0cmFuc2Zvcm1lcn0oJDE6bmFtZSkgJDI6bmFtZSBGUk9NICQzOm5hbWUgJHt3aGVyZVBhdHRlcm59YDtcbiAgICBpZiAoaXNOZXN0ZWQpIHtcbiAgICAgIHFzID0gYFNFTEVDVCBESVNUSU5DVCAke3RyYW5zZm9ybWVyfSgkMTpyYXcpICQyOnJhdyBGUk9NICQzOm5hbWUgJHt3aGVyZVBhdHRlcm59YDtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuX2NsaWVudFxuICAgICAgLmFueShxcywgdmFsdWVzKVxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcbiAgICAgICAgaWYgKGVycm9yLmNvZGUgPT09IFBvc3RncmVzTWlzc2luZ0NvbHVtbkVycm9yKSB7XG4gICAgICAgICAgcmV0dXJuIFtdO1xuICAgICAgICB9XG4gICAgICAgIHRocm93IGVycm9yO1xuICAgICAgfSlcbiAgICAgIC50aGVuKHJlc3VsdHMgPT4ge1xuICAgICAgICBpZiAoIWlzTmVzdGVkKSB7XG4gICAgICAgICAgcmVzdWx0cyA9IHJlc3VsdHMuZmlsdGVyKG9iamVjdCA9PiBvYmplY3RbZmllbGRdICE9PSBudWxsKTtcbiAgICAgICAgICByZXR1cm4gcmVzdWx0cy5tYXAob2JqZWN0ID0+IHtcbiAgICAgICAgICAgIGlmICghaXNQb2ludGVyRmllbGQpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIG9iamVjdFtmaWVsZF07XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgICBfX3R5cGU6ICdQb2ludGVyJyxcbiAgICAgICAgICAgICAgY2xhc3NOYW1lOiBzY2hlbWEuZmllbGRzW2ZpZWxkTmFtZV0udGFyZ2V0Q2xhc3MsXG4gICAgICAgICAgICAgIG9iamVjdElkOiBvYmplY3RbZmllbGRdLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCBjaGlsZCA9IGZpZWxkTmFtZS5zcGxpdCgnLicpWzFdO1xuICAgICAgICByZXR1cm4gcmVzdWx0cy5tYXAob2JqZWN0ID0+IG9iamVjdFtjb2x1bW5dW2NoaWxkXSk7XG4gICAgICB9KVxuICAgICAgLnRoZW4ocmVzdWx0cyA9PlxuICAgICAgICByZXN1bHRzLm1hcChvYmplY3QgPT4gdGhpcy5wb3N0Z3Jlc09iamVjdFRvUGFyc2VPYmplY3QoY2xhc3NOYW1lLCBvYmplY3QsIHNjaGVtYSkpXG4gICAgICApO1xuICB9XG5cbiAgYXN5bmMgYWdncmVnYXRlKFxuICAgIGNsYXNzTmFtZTogc3RyaW5nLFxuICAgIHNjaGVtYTogYW55LFxuICAgIHBpcGVsaW5lOiBhbnksXG4gICAgcmVhZFByZWZlcmVuY2U6ID9zdHJpbmcsXG4gICAgaGludDogP21peGVkLFxuICAgIGV4cGxhaW4/OiBib29sZWFuXG4gICkge1xuICAgIGRlYnVnKCdhZ2dyZWdhdGUnKTtcbiAgICBjb25zdCB2YWx1ZXMgPSBbY2xhc3NOYW1lXTtcbiAgICBsZXQgaW5kZXg6IG51bWJlciA9IDI7XG4gICAgbGV0IGNvbHVtbnM6IHN0cmluZ1tdID0gW107XG4gICAgbGV0IGNvdW50RmllbGQgPSBudWxsO1xuICAgIGxldCBncm91cFZhbHVlcyA9IG51bGw7XG4gICAgbGV0IHdoZXJlUGF0dGVybiA9ICcnO1xuICAgIGxldCBsaW1pdFBhdHRlcm4gPSAnJztcbiAgICBsZXQgc2tpcFBhdHRlcm4gPSAnJztcbiAgICBsZXQgc29ydFBhdHRlcm4gPSAnJztcbiAgICBsZXQgZ3JvdXBQYXR0ZXJuID0gJyc7XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBwaXBlbGluZS5sZW5ndGg7IGkgKz0gMSkge1xuICAgICAgY29uc3Qgc3RhZ2UgPSBwaXBlbGluZVtpXTtcbiAgICAgIGlmIChzdGFnZS4kZ3JvdXApIHtcbiAgICAgICAgZm9yIChjb25zdCBmaWVsZCBpbiBzdGFnZS4kZ3JvdXApIHtcbiAgICAgICAgICBjb25zdCB2YWx1ZSA9IHN0YWdlLiRncm91cFtmaWVsZF07XG4gICAgICAgICAgaWYgKHZhbHVlID09PSBudWxsIHx8IHZhbHVlID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICAgIH1cbiAgICAgICAgICBpZiAoZmllbGQgPT09ICdfaWQnICYmIHR5cGVvZiB2YWx1ZSA9PT0gJ3N0cmluZycgJiYgdmFsdWUgIT09ICcnKSB7XG4gICAgICAgICAgICBjb2x1bW5zLnB1c2goYCQke2luZGV4fTpuYW1lIEFTIFwib2JqZWN0SWRcImApO1xuICAgICAgICAgICAgZ3JvdXBQYXR0ZXJuID0gYEdST1VQIEJZICQke2luZGV4fTpuYW1lYDtcbiAgICAgICAgICAgIHZhbHVlcy5wdXNoKHRyYW5zZm9ybUFnZ3JlZ2F0ZUZpZWxkKHZhbHVlKSk7XG4gICAgICAgICAgICBpbmRleCArPSAxO1xuICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgICAgfVxuICAgICAgICAgIGlmIChmaWVsZCA9PT0gJ19pZCcgJiYgdHlwZW9mIHZhbHVlID09PSAnb2JqZWN0JyAmJiBPYmplY3Qua2V5cyh2YWx1ZSkubGVuZ3RoICE9PSAwKSB7XG4gICAgICAgICAgICBncm91cFZhbHVlcyA9IHZhbHVlO1xuICAgICAgICAgICAgY29uc3QgZ3JvdXBCeUZpZWxkcyA9IFtdO1xuICAgICAgICAgICAgZm9yIChjb25zdCBhbGlhcyBpbiB2YWx1ZSkge1xuICAgICAgICAgICAgICBpZiAodHlwZW9mIHZhbHVlW2FsaWFzXSA9PT0gJ3N0cmluZycgJiYgdmFsdWVbYWxpYXNdKSB7XG4gICAgICAgICAgICAgICAgY29uc3Qgc291cmNlID0gdHJhbnNmb3JtQWdncmVnYXRlRmllbGQodmFsdWVbYWxpYXNdKTtcbiAgICAgICAgICAgICAgICBpZiAoIWdyb3VwQnlGaWVsZHMuaW5jbHVkZXMoYFwiJHtzb3VyY2V9XCJgKSkge1xuICAgICAgICAgICAgICAgICAgZ3JvdXBCeUZpZWxkcy5wdXNoKGBcIiR7c291cmNlfVwiYCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHZhbHVlcy5wdXNoKHNvdXJjZSwgYWxpYXMpO1xuICAgICAgICAgICAgICAgIGNvbHVtbnMucHVzaChgJCR7aW5kZXh9Om5hbWUgQVMgJCR7aW5kZXggKyAxfTpuYW1lYCk7XG4gICAgICAgICAgICAgICAgaW5kZXggKz0gMjtcbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBjb25zdCBvcGVyYXRpb24gPSBPYmplY3Qua2V5cyh2YWx1ZVthbGlhc10pWzBdO1xuICAgICAgICAgICAgICAgIGNvbnN0IHNvdXJjZSA9IHRyYW5zZm9ybUFnZ3JlZ2F0ZUZpZWxkKHZhbHVlW2FsaWFzXVtvcGVyYXRpb25dKTtcbiAgICAgICAgICAgICAgICBpZiAobW9uZ29BZ2dyZWdhdGVUb1Bvc3RncmVzW29wZXJhdGlvbl0pIHtcbiAgICAgICAgICAgICAgICAgIGlmICghZ3JvdXBCeUZpZWxkcy5pbmNsdWRlcyhgXCIke3NvdXJjZX1cImApKSB7XG4gICAgICAgICAgICAgICAgICAgIGdyb3VwQnlGaWVsZHMucHVzaChgXCIke3NvdXJjZX1cImApO1xuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgY29sdW1ucy5wdXNoKFxuICAgICAgICAgICAgICAgICAgICBgRVhUUkFDVCgke1xuICAgICAgICAgICAgICAgICAgICAgIG1vbmdvQWdncmVnYXRlVG9Qb3N0Z3Jlc1tvcGVyYXRpb25dXG4gICAgICAgICAgICAgICAgICAgIH0gRlJPTSAkJHtpbmRleH06bmFtZSBBVCBUSU1FIFpPTkUgJ1VUQycpIEFTICQke2luZGV4ICsgMX06bmFtZWBcbiAgICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgICB2YWx1ZXMucHVzaChzb3VyY2UsIGFsaWFzKTtcbiAgICAgICAgICAgICAgICAgIGluZGV4ICs9IDI7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBncm91cFBhdHRlcm4gPSBgR1JPVVAgQlkgJCR7aW5kZXh9OnJhd2A7XG4gICAgICAgICAgICB2YWx1ZXMucHVzaChncm91cEJ5RmllbGRzLmpvaW4oKSk7XG4gICAgICAgICAgICBpbmRleCArPSAxO1xuICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgICAgfVxuICAgICAgICAgIGlmICh0eXBlb2YgdmFsdWUgPT09ICdvYmplY3QnKSB7XG4gICAgICAgICAgICBpZiAodmFsdWUuJHN1bSkge1xuICAgICAgICAgICAgICBpZiAodHlwZW9mIHZhbHVlLiRzdW0gPT09ICdzdHJpbmcnKSB7XG4gICAgICAgICAgICAgICAgY29sdW1ucy5wdXNoKGBTVU0oJCR7aW5kZXh9Om5hbWUpIEFTICQke2luZGV4ICsgMX06bmFtZWApO1xuICAgICAgICAgICAgICAgIHZhbHVlcy5wdXNoKHRyYW5zZm9ybUFnZ3JlZ2F0ZUZpZWxkKHZhbHVlLiRzdW0pLCBmaWVsZCk7XG4gICAgICAgICAgICAgICAgaW5kZXggKz0gMjtcbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBjb3VudEZpZWxkID0gZmllbGQ7XG4gICAgICAgICAgICAgICAgY29sdW1ucy5wdXNoKGBDT1VOVCgqKSBBUyAkJHtpbmRleH06bmFtZWApO1xuICAgICAgICAgICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkKTtcbiAgICAgICAgICAgICAgICBpbmRleCArPSAxO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAodmFsdWUuJG1heCkge1xuICAgICAgICAgICAgICBjb2x1bW5zLnB1c2goYE1BWCgkJHtpbmRleH06bmFtZSkgQVMgJCR7aW5kZXggKyAxfTpuYW1lYCk7XG4gICAgICAgICAgICAgIHZhbHVlcy5wdXNoKHRyYW5zZm9ybUFnZ3JlZ2F0ZUZpZWxkKHZhbHVlLiRtYXgpLCBmaWVsZCk7XG4gICAgICAgICAgICAgIGluZGV4ICs9IDI7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAodmFsdWUuJG1pbikge1xuICAgICAgICAgICAgICBjb2x1bW5zLnB1c2goYE1JTigkJHtpbmRleH06bmFtZSkgQVMgJCR7aW5kZXggKyAxfTpuYW1lYCk7XG4gICAgICAgICAgICAgIHZhbHVlcy5wdXNoKHRyYW5zZm9ybUFnZ3JlZ2F0ZUZpZWxkKHZhbHVlLiRtaW4pLCBmaWVsZCk7XG4gICAgICAgICAgICAgIGluZGV4ICs9IDI7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAodmFsdWUuJGF2Zykge1xuICAgICAgICAgICAgICBjb2x1bW5zLnB1c2goYEFWRygkJHtpbmRleH06bmFtZSkgQVMgJCR7aW5kZXggKyAxfTpuYW1lYCk7XG4gICAgICAgICAgICAgIHZhbHVlcy5wdXNoKHRyYW5zZm9ybUFnZ3JlZ2F0ZUZpZWxkKHZhbHVlLiRhdmcpLCBmaWVsZCk7XG4gICAgICAgICAgICAgIGluZGV4ICs9IDI7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBjb2x1bW5zLnB1c2goJyonKTtcbiAgICAgIH1cbiAgICAgIGlmIChzdGFnZS4kcHJvamVjdCkge1xuICAgICAgICBpZiAoY29sdW1ucy5pbmNsdWRlcygnKicpKSB7XG4gICAgICAgICAgY29sdW1ucyA9IFtdO1xuICAgICAgICB9XG4gICAgICAgIGZvciAoY29uc3QgZmllbGQgaW4gc3RhZ2UuJHByb2plY3QpIHtcbiAgICAgICAgICBjb25zdCB2YWx1ZSA9IHN0YWdlLiRwcm9qZWN0W2ZpZWxkXTtcbiAgICAgICAgICBpZiAodmFsdWUgPT09IDEgfHwgdmFsdWUgPT09IHRydWUpIHtcbiAgICAgICAgICAgIGNvbHVtbnMucHVzaChgJCR7aW5kZXh9Om5hbWVgKTtcbiAgICAgICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkKTtcbiAgICAgICAgICAgIGluZGV4ICs9IDE7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgICBpZiAoc3RhZ2UuJG1hdGNoKSB7XG4gICAgICAgIGNvbnN0IHBhdHRlcm5zID0gW107XG4gICAgICAgIGNvbnN0IG9yT3JBbmQgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwoc3RhZ2UuJG1hdGNoLCAnJG9yJylcbiAgICAgICAgICA/ICcgT1IgJ1xuICAgICAgICAgIDogJyBBTkQgJztcblxuICAgICAgICBpZiAoc3RhZ2UuJG1hdGNoLiRvcikge1xuICAgICAgICAgIGNvbnN0IGNvbGxhcHNlID0ge307XG4gICAgICAgICAgc3RhZ2UuJG1hdGNoLiRvci5mb3JFYWNoKGVsZW1lbnQgPT4ge1xuICAgICAgICAgICAgZm9yIChjb25zdCBrZXkgaW4gZWxlbWVudCkge1xuICAgICAgICAgICAgICBjb2xsYXBzZVtrZXldID0gZWxlbWVudFtrZXldO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pO1xuICAgICAgICAgIHN0YWdlLiRtYXRjaCA9IGNvbGxhcHNlO1xuICAgICAgICB9XG4gICAgICAgIGZvciAoY29uc3QgZmllbGQgaW4gc3RhZ2UuJG1hdGNoKSB7XG4gICAgICAgICAgY29uc3QgdmFsdWUgPSBzdGFnZS4kbWF0Y2hbZmllbGRdO1xuICAgICAgICAgIGNvbnN0IG1hdGNoUGF0dGVybnMgPSBbXTtcbiAgICAgICAgICBPYmplY3Qua2V5cyhQYXJzZVRvUG9zZ3Jlc0NvbXBhcmF0b3IpLmZvckVhY2goY21wID0+IHtcbiAgICAgICAgICAgIGlmICh2YWx1ZVtjbXBdKSB7XG4gICAgICAgICAgICAgIGNvbnN0IHBnQ29tcGFyYXRvciA9IFBhcnNlVG9Qb3NncmVzQ29tcGFyYXRvcltjbXBdO1xuICAgICAgICAgICAgICBtYXRjaFBhdHRlcm5zLnB1c2goYCQke2luZGV4fTpuYW1lICR7cGdDb21wYXJhdG9yfSAkJHtpbmRleCArIDF9YCk7XG4gICAgICAgICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkLCB0b1Bvc3RncmVzVmFsdWUodmFsdWVbY21wXSkpO1xuICAgICAgICAgICAgICBpbmRleCArPSAyO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pO1xuICAgICAgICAgIGlmIChtYXRjaFBhdHRlcm5zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgICAgIHBhdHRlcm5zLnB1c2goYCgke21hdGNoUGF0dGVybnMuam9pbignIEFORCAnKX0pYCk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGlmIChzY2hlbWEuZmllbGRzW2ZpZWxkXSAmJiBzY2hlbWEuZmllbGRzW2ZpZWxkXS50eXBlICYmIG1hdGNoUGF0dGVybnMubGVuZ3RoID09PSAwKSB7XG4gICAgICAgICAgICBwYXR0ZXJucy5wdXNoKGAkJHtpbmRleH06bmFtZSA9ICQke2luZGV4ICsgMX1gKTtcbiAgICAgICAgICAgIHZhbHVlcy5wdXNoKGZpZWxkLCB2YWx1ZSk7XG4gICAgICAgICAgICBpbmRleCArPSAyO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICB3aGVyZVBhdHRlcm4gPSBwYXR0ZXJucy5sZW5ndGggPiAwID8gYFdIRVJFICR7cGF0dGVybnMuam9pbihgICR7b3JPckFuZH0gYCl9YCA6ICcnO1xuICAgICAgfVxuICAgICAgaWYgKHN0YWdlLiRsaW1pdCkge1xuICAgICAgICBsaW1pdFBhdHRlcm4gPSBgTElNSVQgJCR7aW5kZXh9YDtcbiAgICAgICAgdmFsdWVzLnB1c2goc3RhZ2UuJGxpbWl0KTtcbiAgICAgICAgaW5kZXggKz0gMTtcbiAgICAgIH1cbiAgICAgIGlmIChzdGFnZS4kc2tpcCkge1xuICAgICAgICBza2lwUGF0dGVybiA9IGBPRkZTRVQgJCR7aW5kZXh9YDtcbiAgICAgICAgdmFsdWVzLnB1c2goc3RhZ2UuJHNraXApO1xuICAgICAgICBpbmRleCArPSAxO1xuICAgICAgfVxuICAgICAgaWYgKHN0YWdlLiRzb3J0KSB7XG4gICAgICAgIGNvbnN0IHNvcnQgPSBzdGFnZS4kc29ydDtcbiAgICAgICAgY29uc3Qga2V5cyA9IE9iamVjdC5rZXlzKHNvcnQpO1xuICAgICAgICBjb25zdCBzb3J0aW5nID0ga2V5c1xuICAgICAgICAgIC5tYXAoa2V5ID0+IHtcbiAgICAgICAgICAgIGNvbnN0IHRyYW5zZm9ybWVyID0gc29ydFtrZXldID09PSAxID8gJ0FTQycgOiAnREVTQyc7XG4gICAgICAgICAgICBjb25zdCBvcmRlciA9IGAkJHtpbmRleH06bmFtZSAke3RyYW5zZm9ybWVyfWA7XG4gICAgICAgICAgICBpbmRleCArPSAxO1xuICAgICAgICAgICAgcmV0dXJuIG9yZGVyO1xuICAgICAgICAgIH0pXG4gICAgICAgICAgLmpvaW4oKTtcbiAgICAgICAgdmFsdWVzLnB1c2goLi4ua2V5cyk7XG4gICAgICAgIHNvcnRQYXR0ZXJuID0gc29ydCAhPT0gdW5kZWZpbmVkICYmIHNvcnRpbmcubGVuZ3RoID4gMCA/IGBPUkRFUiBCWSAke3NvcnRpbmd9YCA6ICcnO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChncm91cFBhdHRlcm4pIHtcbiAgICAgIGNvbHVtbnMuZm9yRWFjaCgoZSwgaSwgYSkgPT4ge1xuICAgICAgICBpZiAoZSAmJiBlLnRyaW0oKSA9PT0gJyonKSB7XG4gICAgICAgICAgYVtpXSA9ICcnO1xuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBjb25zdCBvcmlnaW5hbFF1ZXJ5ID0gYFNFTEVDVCAke2NvbHVtbnNcbiAgICAgIC5maWx0ZXIoQm9vbGVhbilcbiAgICAgIC5qb2luKCl9IEZST00gJDE6bmFtZSAke3doZXJlUGF0dGVybn0gJHtza2lwUGF0dGVybn0gJHtncm91cFBhdHRlcm59ICR7c29ydFBhdHRlcm59ICR7bGltaXRQYXR0ZXJufWA7XG4gICAgY29uc3QgcXMgPSBleHBsYWluID8gdGhpcy5jcmVhdGVFeHBsYWluYWJsZVF1ZXJ5KG9yaWdpbmFsUXVlcnkpIDogb3JpZ2luYWxRdWVyeTtcbiAgICByZXR1cm4gdGhpcy5fY2xpZW50LmFueShxcywgdmFsdWVzKS50aGVuKGEgPT4ge1xuICAgICAgaWYgKGV4cGxhaW4pIHtcbiAgICAgICAgcmV0dXJuIGE7XG4gICAgICB9XG4gICAgICBjb25zdCByZXN1bHRzID0gYS5tYXAob2JqZWN0ID0+IHRoaXMucG9zdGdyZXNPYmplY3RUb1BhcnNlT2JqZWN0KGNsYXNzTmFtZSwgb2JqZWN0LCBzY2hlbWEpKTtcbiAgICAgIHJlc3VsdHMuZm9yRWFjaChyZXN1bHQgPT4ge1xuICAgICAgICBpZiAoIU9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChyZXN1bHQsICdvYmplY3RJZCcpKSB7XG4gICAgICAgICAgcmVzdWx0Lm9iamVjdElkID0gbnVsbDtcbiAgICAgICAgfVxuICAgICAgICBpZiAoZ3JvdXBWYWx1ZXMpIHtcbiAgICAgICAgICByZXN1bHQub2JqZWN0SWQgPSB7fTtcbiAgICAgICAgICBmb3IgKGNvbnN0IGtleSBpbiBncm91cFZhbHVlcykge1xuICAgICAgICAgICAgcmVzdWx0Lm9iamVjdElkW2tleV0gPSByZXN1bHRba2V5XTtcbiAgICAgICAgICAgIGRlbGV0ZSByZXN1bHRba2V5XTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGNvdW50RmllbGQpIHtcbiAgICAgICAgICByZXN1bHRbY291bnRGaWVsZF0gPSBwYXJzZUludChyZXN1bHRbY291bnRGaWVsZF0sIDEwKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgICByZXR1cm4gcmVzdWx0cztcbiAgICB9KTtcbiAgfVxuXG4gIGFzeW5jIHBlcmZvcm1Jbml0aWFsaXphdGlvbih7IFZvbGF0aWxlQ2xhc3Nlc1NjaGVtYXMgfTogYW55KSB7XG4gICAgLy8gVE9ETzogVGhpcyBtZXRob2QgbmVlZHMgdG8gYmUgcmV3cml0dGVuIHRvIG1ha2UgcHJvcGVyIHVzZSBvZiBjb25uZWN0aW9ucyAoQHZpdGFseS10KVxuICAgIGRlYnVnKCdwZXJmb3JtSW5pdGlhbGl6YXRpb24nKTtcbiAgICBhd2FpdCB0aGlzLl9lbnN1cmVTY2hlbWFDb2xsZWN0aW9uRXhpc3RzKCk7XG4gICAgY29uc3QgcHJvbWlzZXMgPSBWb2xhdGlsZUNsYXNzZXNTY2hlbWFzLm1hcChzY2hlbWEgPT4ge1xuICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlVGFibGUoc2NoZW1hLmNsYXNzTmFtZSwgc2NoZW1hKVxuICAgICAgICAuY2F0Y2goZXJyID0+IHtcbiAgICAgICAgICBpZiAoXG4gICAgICAgICAgICBlcnIuY29kZSA9PT0gUG9zdGdyZXNEdXBsaWNhdGVSZWxhdGlvbkVycm9yIHx8XG4gICAgICAgICAgICBlcnIuY29kZSA9PT0gUGFyc2UuRXJyb3IuSU5WQUxJRF9DTEFTU19OQU1FXG4gICAgICAgICAgKSB7XG4gICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHRocm93IGVycjtcbiAgICAgICAgfSlcbiAgICAgICAgLnRoZW4oKCkgPT4gdGhpcy5zY2hlbWFVcGdyYWRlKHNjaGVtYS5jbGFzc05hbWUsIHNjaGVtYSkpO1xuICAgIH0pO1xuICAgIHByb21pc2VzLnB1c2godGhpcy5fbGlzdGVuVG9TY2hlbWEoKSk7XG4gICAgcmV0dXJuIFByb21pc2UuYWxsKHByb21pc2VzKVxuICAgICAgLnRoZW4oKCkgPT4ge1xuICAgICAgICByZXR1cm4gdGhpcy5fY2xpZW50LnR4KCdwZXJmb3JtLWluaXRpYWxpemF0aW9uJywgYXN5bmMgdCA9PiB7XG4gICAgICAgICAgYXdhaXQgdC5ub25lKHNxbC5taXNjLmpzb25PYmplY3RTZXRLZXlzKTtcbiAgICAgICAgICBhd2FpdCB0Lm5vbmUoc3FsLmFycmF5LmFkZCk7XG4gICAgICAgICAgYXdhaXQgdC5ub25lKHNxbC5hcnJheS5hZGRVbmlxdWUpO1xuICAgICAgICAgIGF3YWl0IHQubm9uZShzcWwuYXJyYXkucmVtb3ZlKTtcbiAgICAgICAgICBhd2FpdCB0Lm5vbmUoc3FsLmFycmF5LmNvbnRhaW5zQWxsKTtcbiAgICAgICAgICBhd2FpdCB0Lm5vbmUoc3FsLmFycmF5LmNvbnRhaW5zQWxsUmVnZXgpO1xuICAgICAgICAgIGF3YWl0IHQubm9uZShzcWwuYXJyYXkuY29udGFpbnMpO1xuICAgICAgICAgIHJldHVybiB0LmN0eDtcbiAgICAgICAgfSk7XG4gICAgICB9KVxuICAgICAgLnRoZW4oY3R4ID0+IHtcbiAgICAgICAgZGVidWcoYGluaXRpYWxpemF0aW9uRG9uZSBpbiAke2N0eC5kdXJhdGlvbn1gKTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICAvKiBlc2xpbnQtZGlzYWJsZSBuby1jb25zb2xlICovXG4gICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xuICAgICAgfSk7XG4gIH1cblxuICBhc3luYyBjcmVhdGVJbmRleGVzKGNsYXNzTmFtZTogc3RyaW5nLCBpbmRleGVzOiBhbnksIGNvbm46ID9hbnkpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICByZXR1cm4gKGNvbm4gfHwgdGhpcy5fY2xpZW50KS50eCh0ID0+XG4gICAgICB0LmJhdGNoKFxuICAgICAgICBpbmRleGVzLm1hcChpID0+IHtcbiAgICAgICAgICByZXR1cm4gdC5ub25lKCdDUkVBVEUgSU5ERVggSUYgTk9UIEVYSVNUUyAkMTpuYW1lIE9OICQyOm5hbWUgKCQzOm5hbWUpJywgW1xuICAgICAgICAgICAgaS5uYW1lLFxuICAgICAgICAgICAgY2xhc3NOYW1lLFxuICAgICAgICAgICAgaS5rZXksXG4gICAgICAgICAgXSk7XG4gICAgICAgIH0pXG4gICAgICApXG4gICAgKTtcbiAgfVxuXG4gIGFzeW5jIGNyZWF0ZUluZGV4ZXNJZk5lZWRlZChcbiAgICBjbGFzc05hbWU6IHN0cmluZyxcbiAgICBmaWVsZE5hbWU6IHN0cmluZyxcbiAgICB0eXBlOiBhbnksXG4gICAgY29ubjogP2FueVxuICApOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBhd2FpdCAoY29ubiB8fCB0aGlzLl9jbGllbnQpLm5vbmUoJ0NSRUFURSBJTkRFWCBJRiBOT1QgRVhJU1RTICQxOm5hbWUgT04gJDI6bmFtZSAoJDM6bmFtZSknLCBbXG4gICAgICBmaWVsZE5hbWUsXG4gICAgICBjbGFzc05hbWUsXG4gICAgICB0eXBlLFxuICAgIF0pO1xuICB9XG5cbiAgYXN5bmMgZHJvcEluZGV4ZXMoY2xhc3NOYW1lOiBzdHJpbmcsIGluZGV4ZXM6IGFueSwgY29ubjogYW55KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgcXVlcmllcyA9IGluZGV4ZXMubWFwKGkgPT4gKHtcbiAgICAgIHF1ZXJ5OiAnRFJPUCBJTkRFWCAkMTpuYW1lJyxcbiAgICAgIHZhbHVlczogaSxcbiAgICB9KSk7XG4gICAgYXdhaXQgKGNvbm4gfHwgdGhpcy5fY2xpZW50KS50eCh0ID0+IHQubm9uZSh0aGlzLl9wZ3AuaGVscGVycy5jb25jYXQocXVlcmllcykpKTtcbiAgfVxuXG4gIGFzeW5jIGdldEluZGV4ZXMoY2xhc3NOYW1lOiBzdHJpbmcpIHtcbiAgICBjb25zdCBxcyA9ICdTRUxFQ1QgKiBGUk9NIHBnX2luZGV4ZXMgV0hFUkUgdGFibGVuYW1lID0gJHtjbGFzc05hbWV9JztcbiAgICByZXR1cm4gdGhpcy5fY2xpZW50LmFueShxcywgeyBjbGFzc05hbWUgfSk7XG4gIH1cblxuICBhc3luYyB1cGRhdGVTY2hlbWFXaXRoSW5kZXhlcygpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XG4gIH1cblxuICAvLyBVc2VkIGZvciB0ZXN0aW5nIHB1cnBvc2VzXG4gIGFzeW5jIHVwZGF0ZUVzdGltYXRlZENvdW50KGNsYXNzTmFtZTogc3RyaW5nKSB7XG4gICAgcmV0dXJuIHRoaXMuX2NsaWVudC5ub25lKCdBTkFMWVpFICQxOm5hbWUnLCBbY2xhc3NOYW1lXSk7XG4gIH1cblxuICBhc3luYyBjcmVhdGVUcmFuc2FjdGlvbmFsU2Vzc2lvbigpOiBQcm9taXNlPGFueT4ge1xuICAgIHJldHVybiBuZXcgUHJvbWlzZShyZXNvbHZlID0+IHtcbiAgICAgIGNvbnN0IHRyYW5zYWN0aW9uYWxTZXNzaW9uID0ge307XG4gICAgICB0cmFuc2FjdGlvbmFsU2Vzc2lvbi5yZXN1bHQgPSB0aGlzLl9jbGllbnQudHgodCA9PiB7XG4gICAgICAgIHRyYW5zYWN0aW9uYWxTZXNzaW9uLnQgPSB0O1xuICAgICAgICB0cmFuc2FjdGlvbmFsU2Vzc2lvbi5wcm9taXNlID0gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XG4gICAgICAgICAgdHJhbnNhY3Rpb25hbFNlc3Npb24ucmVzb2x2ZSA9IHJlc29sdmU7XG4gICAgICAgIH0pO1xuICAgICAgICB0cmFuc2FjdGlvbmFsU2Vzc2lvbi5iYXRjaCA9IFtdO1xuICAgICAgICByZXNvbHZlKHRyYW5zYWN0aW9uYWxTZXNzaW9uKTtcbiAgICAgICAgcmV0dXJuIHRyYW5zYWN0aW9uYWxTZXNzaW9uLnByb21pc2U7XG4gICAgICB9KTtcbiAgICB9KTtcbiAgfVxuXG4gIGNvbW1pdFRyYW5zYWN0aW9uYWxTZXNzaW9uKHRyYW5zYWN0aW9uYWxTZXNzaW9uOiBhbnkpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICB0cmFuc2FjdGlvbmFsU2Vzc2lvbi5yZXNvbHZlKHRyYW5zYWN0aW9uYWxTZXNzaW9uLnQuYmF0Y2godHJhbnNhY3Rpb25hbFNlc3Npb24uYmF0Y2gpKTtcbiAgICByZXR1cm4gdHJhbnNhY3Rpb25hbFNlc3Npb24ucmVzdWx0O1xuICB9XG5cbiAgYWJvcnRUcmFuc2FjdGlvbmFsU2Vzc2lvbih0cmFuc2FjdGlvbmFsU2Vzc2lvbjogYW55KTogUHJvbWlzZTx2b2lkPiB7XG4gICAgY29uc3QgcmVzdWx0ID0gdHJhbnNhY3Rpb25hbFNlc3Npb24ucmVzdWx0LmNhdGNoKCk7XG4gICAgdHJhbnNhY3Rpb25hbFNlc3Npb24uYmF0Y2gucHVzaChQcm9taXNlLnJlamVjdCgpKTtcbiAgICB0cmFuc2FjdGlvbmFsU2Vzc2lvbi5yZXNvbHZlKHRyYW5zYWN0aW9uYWxTZXNzaW9uLnQuYmF0Y2godHJhbnNhY3Rpb25hbFNlc3Npb24uYmF0Y2gpKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgYXN5bmMgZW5zdXJlSW5kZXgoXG4gICAgY2xhc3NOYW1lOiBzdHJpbmcsXG4gICAgc2NoZW1hOiBTY2hlbWFUeXBlLFxuICAgIGZpZWxkTmFtZXM6IHN0cmluZ1tdLFxuICAgIGluZGV4TmFtZTogP3N0cmluZyxcbiAgICBjYXNlSW5zZW5zaXRpdmU6IGJvb2xlYW4gPSBmYWxzZSxcbiAgICBvcHRpb25zPzogT2JqZWN0ID0ge31cbiAgKTogUHJvbWlzZTxhbnk+IHtcbiAgICBjb25zdCBjb25uID0gb3B0aW9ucy5jb25uICE9PSB1bmRlZmluZWQgPyBvcHRpb25zLmNvbm4gOiB0aGlzLl9jbGllbnQ7XG4gICAgY29uc3QgZGVmYXVsdEluZGV4TmFtZSA9IGBwYXJzZV9kZWZhdWx0XyR7ZmllbGROYW1lcy5zb3J0KCkuam9pbignXycpfWA7XG4gICAgY29uc3QgaW5kZXhOYW1lT3B0aW9uczogT2JqZWN0ID1cbiAgICAgIGluZGV4TmFtZSAhPSBudWxsID8geyBuYW1lOiBpbmRleE5hbWUgfSA6IHsgbmFtZTogZGVmYXVsdEluZGV4TmFtZSB9O1xuICAgIGNvbnN0IGNvbnN0cmFpbnRQYXR0ZXJucyA9IGNhc2VJbnNlbnNpdGl2ZVxuICAgICAgPyBmaWVsZE5hbWVzLm1hcCgoZmllbGROYW1lLCBpbmRleCkgPT4gYGxvd2VyKCQke2luZGV4ICsgM306bmFtZSkgdmFyY2hhcl9wYXR0ZXJuX29wc2ApXG4gICAgICA6IGZpZWxkTmFtZXMubWFwKChmaWVsZE5hbWUsIGluZGV4KSA9PiBgJCR7aW5kZXggKyAzfTpuYW1lYCk7XG4gICAgY29uc3QgcXMgPSBgQ1JFQVRFIElOREVYIElGIE5PVCBFWElTVFMgJDE6bmFtZSBPTiAkMjpuYW1lICgke2NvbnN0cmFpbnRQYXR0ZXJucy5qb2luKCl9KWA7XG4gICAgYXdhaXQgY29ubi5ub25lKHFzLCBbaW5kZXhOYW1lT3B0aW9ucy5uYW1lLCBjbGFzc05hbWUsIC4uLmZpZWxkTmFtZXNdKS5jYXRjaChlcnJvciA9PiB7XG4gICAgICBpZiAoXG4gICAgICAgIGVycm9yLmNvZGUgPT09IFBvc3RncmVzRHVwbGljYXRlUmVsYXRpb25FcnJvciAmJlxuICAgICAgICBlcnJvci5tZXNzYWdlLmluY2x1ZGVzKGluZGV4TmFtZU9wdGlvbnMubmFtZSlcbiAgICAgICkge1xuICAgICAgICAvLyBJbmRleCBhbHJlYWR5IGV4aXN0cy4gSWdub3JlIGVycm9yLlxuICAgICAgfSBlbHNlIGlmIChcbiAgICAgICAgZXJyb3IuY29kZSA9PT0gUG9zdGdyZXNVbmlxdWVJbmRleFZpb2xhdGlvbkVycm9yICYmXG4gICAgICAgIGVycm9yLm1lc3NhZ2UuaW5jbHVkZXMoaW5kZXhOYW1lT3B0aW9ucy5uYW1lKVxuICAgICAgKSB7XG4gICAgICAgIC8vIENhc3QgdGhlIGVycm9yIGludG8gdGhlIHByb3BlciBwYXJzZSBlcnJvclxuICAgICAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoXG4gICAgICAgICAgUGFyc2UuRXJyb3IuRFVQTElDQVRFX1ZBTFVFLFxuICAgICAgICAgICdBIGR1cGxpY2F0ZSB2YWx1ZSBmb3IgYSBmaWVsZCB3aXRoIHVuaXF1ZSB2YWx1ZXMgd2FzIHByb3ZpZGVkJ1xuICAgICAgICApO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhyb3cgZXJyb3I7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cbn1cblxuZnVuY3Rpb24gY29udmVydFBvbHlnb25Ub1NRTChwb2x5Z29uKSB7XG4gIGlmIChwb2x5Z29uLmxlbmd0aCA8IDMpIHtcbiAgICB0aHJvdyBuZXcgUGFyc2UuRXJyb3IoUGFyc2UuRXJyb3IuSU5WQUxJRF9KU09OLCBgUG9seWdvbiBtdXN0IGhhdmUgYXQgbGVhc3QgMyB2YWx1ZXNgKTtcbiAgfVxuICBpZiAoXG4gICAgcG9seWdvblswXVswXSAhPT0gcG9seWdvbltwb2x5Z29uLmxlbmd0aCAtIDFdWzBdIHx8XG4gICAgcG9seWdvblswXVsxXSAhPT0gcG9seWdvbltwb2x5Z29uLmxlbmd0aCAtIDFdWzFdXG4gICkge1xuICAgIHBvbHlnb24ucHVzaChwb2x5Z29uWzBdKTtcbiAgfVxuICBjb25zdCB1bmlxdWUgPSBwb2x5Z29uLmZpbHRlcigoaXRlbSwgaW5kZXgsIGFyKSA9PiB7XG4gICAgbGV0IGZvdW5kSW5kZXggPSAtMTtcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGFyLmxlbmd0aDsgaSArPSAxKSB7XG4gICAgICBjb25zdCBwdCA9IGFyW2ldO1xuICAgICAgaWYgKHB0WzBdID09PSBpdGVtWzBdICYmIHB0WzFdID09PSBpdGVtWzFdKSB7XG4gICAgICAgIGZvdW5kSW5kZXggPSBpO1xuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIGZvdW5kSW5kZXggPT09IGluZGV4O1xuICB9KTtcbiAgaWYgKHVuaXF1ZS5sZW5ndGggPCAzKSB7XG4gICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFxuICAgICAgUGFyc2UuRXJyb3IuSU5URVJOQUxfU0VSVkVSX0VSUk9SLFxuICAgICAgJ0dlb0pTT046IExvb3AgbXVzdCBoYXZlIGF0IGxlYXN0IDMgZGlmZmVyZW50IHZlcnRpY2VzJ1xuICAgICk7XG4gIH1cbiAgY29uc3QgcG9pbnRzID0gcG9seWdvblxuICAgIC5tYXAocG9pbnQgPT4ge1xuICAgICAgUGFyc2UuR2VvUG9pbnQuX3ZhbGlkYXRlKHBhcnNlRmxvYXQocG9pbnRbMV0pLCBwYXJzZUZsb2F0KHBvaW50WzBdKSk7XG4gICAgICByZXR1cm4gYCgke3BvaW50WzFdfSwgJHtwb2ludFswXX0pYDtcbiAgICB9KVxuICAgIC5qb2luKCcsICcpO1xuICByZXR1cm4gYCgke3BvaW50c30pYDtcbn1cblxuZnVuY3Rpb24gcmVtb3ZlV2hpdGVTcGFjZShyZWdleCkge1xuICBpZiAoIXJlZ2V4LmVuZHNXaXRoKCdcXG4nKSkge1xuICAgIHJlZ2V4ICs9ICdcXG4nO1xuICB9XG5cbiAgLy8gcmVtb3ZlIG5vbiBlc2NhcGVkIGNvbW1lbnRzXG4gIHJldHVybiAoXG4gICAgcmVnZXhcbiAgICAgIC5yZXBsYWNlKC8oW15cXFxcXSkjLipcXG4vZ2ltLCAnJDEnKVxuICAgICAgLy8gcmVtb3ZlIGxpbmVzIHN0YXJ0aW5nIHdpdGggYSBjb21tZW50XG4gICAgICAucmVwbGFjZSgvXiMuKlxcbi9naW0sICcnKVxuICAgICAgLy8gcmVtb3ZlIG5vbiBlc2NhcGVkIHdoaXRlc3BhY2VcbiAgICAgIC5yZXBsYWNlKC8oW15cXFxcXSlcXHMrL2dpbSwgJyQxJylcbiAgICAgIC8vIHJlbW92ZSB3aGl0ZXNwYWNlIGF0IHRoZSBiZWdpbm5pbmcgb2YgYSBsaW5lXG4gICAgICAucmVwbGFjZSgvXlxccysvLCAnJylcbiAgICAgIC50cmltKClcbiAgKTtcbn1cblxuZnVuY3Rpb24gcHJvY2Vzc1JlZ2V4UGF0dGVybihzKSB7XG4gIGlmIChzICYmIHMuc3RhcnRzV2l0aCgnXicpKSB7XG4gICAgLy8gcmVnZXggZm9yIHN0YXJ0c1dpdGhcbiAgICByZXR1cm4gJ14nICsgbGl0ZXJhbGl6ZVJlZ2V4UGFydChzLnNsaWNlKDEpKTtcbiAgfSBlbHNlIGlmIChzICYmIHMuZW5kc1dpdGgoJyQnKSkge1xuICAgIC8vIHJlZ2V4IGZvciBlbmRzV2l0aFxuICAgIHJldHVybiBsaXRlcmFsaXplUmVnZXhQYXJ0KHMuc2xpY2UoMCwgcy5sZW5ndGggLSAxKSkgKyAnJCc7XG4gIH1cblxuICAvLyByZWdleCBmb3IgY29udGFpbnNcbiAgcmV0dXJuIGxpdGVyYWxpemVSZWdleFBhcnQocyk7XG59XG5cbmZ1bmN0aW9uIGlzU3RhcnRzV2l0aFJlZ2V4KHZhbHVlKSB7XG4gIGlmICghdmFsdWUgfHwgdHlwZW9mIHZhbHVlICE9PSAnc3RyaW5nJyB8fCAhdmFsdWUuc3RhcnRzV2l0aCgnXicpKSB7XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgY29uc3QgbWF0Y2hlcyA9IHZhbHVlLm1hdGNoKC9cXF5cXFxcUS4qXFxcXEUvKTtcbiAgcmV0dXJuICEhbWF0Y2hlcztcbn1cblxuZnVuY3Rpb24gaXNBbGxWYWx1ZXNSZWdleE9yTm9uZSh2YWx1ZXMpIHtcbiAgaWYgKCF2YWx1ZXMgfHwgIUFycmF5LmlzQXJyYXkodmFsdWVzKSB8fCB2YWx1ZXMubGVuZ3RoID09PSAwKSB7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICBjb25zdCBmaXJzdFZhbHVlc0lzUmVnZXggPSBpc1N0YXJ0c1dpdGhSZWdleCh2YWx1ZXNbMF0uJHJlZ2V4KTtcbiAgaWYgKHZhbHVlcy5sZW5ndGggPT09IDEpIHtcbiAgICByZXR1cm4gZmlyc3RWYWx1ZXNJc1JlZ2V4O1xuICB9XG5cbiAgZm9yIChsZXQgaSA9IDEsIGxlbmd0aCA9IHZhbHVlcy5sZW5ndGg7IGkgPCBsZW5ndGg7ICsraSkge1xuICAgIGlmIChmaXJzdFZhbHVlc0lzUmVnZXggIT09IGlzU3RhcnRzV2l0aFJlZ2V4KHZhbHVlc1tpXS4kcmVnZXgpKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHRydWU7XG59XG5cbmZ1bmN0aW9uIGlzQW55VmFsdWVSZWdleFN0YXJ0c1dpdGgodmFsdWVzKSB7XG4gIHJldHVybiB2YWx1ZXMuc29tZShmdW5jdGlvbiAodmFsdWUpIHtcbiAgICByZXR1cm4gaXNTdGFydHNXaXRoUmVnZXgodmFsdWUuJHJlZ2V4KTtcbiAgfSk7XG59XG5cbmZ1bmN0aW9uIGNyZWF0ZUxpdGVyYWxSZWdleChyZW1haW5pbmcpIHtcbiAgcmV0dXJuIHJlbWFpbmluZ1xuICAgIC5zcGxpdCgnJylcbiAgICAubWFwKGMgPT4ge1xuICAgICAgY29uc3QgcmVnZXggPSBSZWdFeHAoJ1swLTkgXXxcXFxccHtMfScsICd1Jyk7IC8vIFN1cHBvcnQgYWxsIHVuaWNvZGUgbGV0dGVyIGNoYXJzXG4gICAgICBpZiAoYy5tYXRjaChyZWdleCkgIT09IG51bGwpIHtcbiAgICAgICAgLy8gZG9uJ3QgZXNjYXBlIGFscGhhbnVtZXJpYyBjaGFyYWN0ZXJzXG4gICAgICAgIHJldHVybiBjO1xuICAgICAgfVxuICAgICAgLy8gZXNjYXBlIGV2ZXJ5dGhpbmcgZWxzZSAoc2luZ2xlIHF1b3RlcyB3aXRoIHNpbmdsZSBxdW90ZXMsIGV2ZXJ5dGhpbmcgZWxzZSB3aXRoIGEgYmFja3NsYXNoKVxuICAgICAgcmV0dXJuIGMgPT09IGAnYCA/IGAnJ2AgOiBgXFxcXCR7Y31gO1xuICAgIH0pXG4gICAgLmpvaW4oJycpO1xufVxuXG5mdW5jdGlvbiBsaXRlcmFsaXplUmVnZXhQYXJ0KHM6IHN0cmluZykge1xuICBjb25zdCBtYXRjaGVyMSA9IC9cXFxcUSgoPyFcXFxcRSkuKilcXFxcRSQvO1xuICBjb25zdCByZXN1bHQxOiBhbnkgPSBzLm1hdGNoKG1hdGNoZXIxKTtcbiAgaWYgKHJlc3VsdDEgJiYgcmVzdWx0MS5sZW5ndGggPiAxICYmIHJlc3VsdDEuaW5kZXggPiAtMSkge1xuICAgIC8vIHByb2Nlc3MgcmVnZXggdGhhdCBoYXMgYSBiZWdpbm5pbmcgYW5kIGFuIGVuZCBzcGVjaWZpZWQgZm9yIHRoZSBsaXRlcmFsIHRleHRcbiAgICBjb25zdCBwcmVmaXggPSBzLnN1YnN0cigwLCByZXN1bHQxLmluZGV4KTtcbiAgICBjb25zdCByZW1haW5pbmcgPSByZXN1bHQxWzFdO1xuXG4gICAgcmV0dXJuIGxpdGVyYWxpemVSZWdleFBhcnQocHJlZml4KSArIGNyZWF0ZUxpdGVyYWxSZWdleChyZW1haW5pbmcpO1xuICB9XG5cbiAgLy8gcHJvY2VzcyByZWdleCB0aGF0IGhhcyBhIGJlZ2lubmluZyBzcGVjaWZpZWQgZm9yIHRoZSBsaXRlcmFsIHRleHRcbiAgY29uc3QgbWF0Y2hlcjIgPSAvXFxcXFEoKD8hXFxcXEUpLiopJC87XG4gIGNvbnN0IHJlc3VsdDI6IGFueSA9IHMubWF0Y2gobWF0Y2hlcjIpO1xuICBpZiAocmVzdWx0MiAmJiByZXN1bHQyLmxlbmd0aCA+IDEgJiYgcmVzdWx0Mi5pbmRleCA+IC0xKSB7XG4gICAgY29uc3QgcHJlZml4ID0gcy5zdWJzdHIoMCwgcmVzdWx0Mi5pbmRleCk7XG4gICAgY29uc3QgcmVtYWluaW5nID0gcmVzdWx0MlsxXTtcblxuICAgIHJldHVybiBsaXRlcmFsaXplUmVnZXhQYXJ0KHByZWZpeCkgKyBjcmVhdGVMaXRlcmFsUmVnZXgocmVtYWluaW5nKTtcbiAgfVxuXG4gIC8vIHJlbW92ZSBhbGwgaW5zdGFuY2VzIG9mIFxcUSBhbmQgXFxFIGZyb20gdGhlIHJlbWFpbmluZyB0ZXh0ICYgZXNjYXBlIHNpbmdsZSBxdW90ZXNcbiAgcmV0dXJuIHNcbiAgICAucmVwbGFjZSgvKFteXFxcXF0pKFxcXFxFKS8sICckMScpXG4gICAgLnJlcGxhY2UoLyhbXlxcXFxdKShcXFxcUSkvLCAnJDEnKVxuICAgIC5yZXBsYWNlKC9eXFxcXEUvLCAnJylcbiAgICAucmVwbGFjZSgvXlxcXFxRLywgJycpXG4gICAgLnJlcGxhY2UoLyhbXiddKScvLCBgJDEnJ2ApXG4gICAgLnJlcGxhY2UoL14nKFteJ10pLywgYCcnJDFgKTtcbn1cblxudmFyIEdlb1BvaW50Q29kZXIgPSB7XG4gIGlzVmFsaWRKU09OKHZhbHVlKSB7XG4gICAgcmV0dXJuIHR5cGVvZiB2YWx1ZSA9PT0gJ29iamVjdCcgJiYgdmFsdWUgIT09IG51bGwgJiYgdmFsdWUuX190eXBlID09PSAnR2VvUG9pbnQnO1xuICB9LFxufTtcblxuZXhwb3J0IGRlZmF1bHQgUG9zdGdyZXNTdG9yYWdlQWRhcHRlcjtcbiJdfQ==