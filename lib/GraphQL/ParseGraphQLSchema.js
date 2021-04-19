"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ParseGraphQLSchema = void 0;

var _node = _interopRequireDefault(require("parse/node"));

var _graphql = require("graphql");

var _stitch = require("@graphql-tools/stitch");

var _utils = require("@graphql-tools/utils");

var _requiredParameter = _interopRequireDefault(require("../requiredParameter"));

var defaultGraphQLTypes = _interopRequireWildcard(require("./loaders/defaultGraphQLTypes"));

var parseClassTypes = _interopRequireWildcard(require("./loaders/parseClassTypes"));

var parseClassQueries = _interopRequireWildcard(require("./loaders/parseClassQueries"));

var parseClassMutations = _interopRequireWildcard(require("./loaders/parseClassMutations"));

var defaultGraphQLQueries = _interopRequireWildcard(require("./loaders/defaultGraphQLQueries"));

var defaultGraphQLMutations = _interopRequireWildcard(require("./loaders/defaultGraphQLMutations"));

var _ParseGraphQLController = _interopRequireWildcard(require("../Controllers/ParseGraphQLController"));

var _DatabaseController = _interopRequireDefault(require("../Controllers/DatabaseController"));

var _SchemaCache = _interopRequireDefault(require("../Adapters/Cache/SchemaCache"));

var _parseGraphQLUtils = require("./parseGraphQLUtils");

var schemaDirectives = _interopRequireWildcard(require("./loaders/schemaDirectives"));

var schemaTypes = _interopRequireWildcard(require("./loaders/schemaTypes"));

var _triggers = require("../triggers");

var defaultRelaySchema = _interopRequireWildcard(require("./loaders/defaultRelaySchema"));

function _getRequireWildcardCache() { if (typeof WeakMap !== "function") return null; var cache = new WeakMap(); _getRequireWildcardCache = function () { return cache; }; return cache; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

const RESERVED_GRAPHQL_TYPE_NAMES = ['String', 'Boolean', 'Int', 'Float', 'ID', 'ArrayResult', 'Query', 'Mutation', 'Subscription', 'CreateFileInput', 'CreateFilePayload', 'Viewer', 'SignUpInput', 'SignUpPayload', 'LogInInput', 'LogInPayload', 'LogOutInput', 'LogOutPayload', 'CloudCodeFunction', 'CallCloudCodeInput', 'CallCloudCodePayload', 'CreateClassInput', 'CreateClassPayload', 'UpdateClassInput', 'UpdateClassPayload', 'DeleteClassInput', 'DeleteClassPayload', 'PageInfo'];
const RESERVED_GRAPHQL_QUERY_NAMES = ['health', 'viewer', 'class', 'classes'];
const RESERVED_GRAPHQL_MUTATION_NAMES = ['signUp', 'logIn', 'logOut', 'createFile', 'callCloudCode', 'createClass', 'updateClass', 'deleteClass'];

class ParseGraphQLSchema {
  constructor(params = {}) {
    this.parseGraphQLController = params.parseGraphQLController || (0, _requiredParameter.default)('You must provide a parseGraphQLController instance!');
    this.databaseController = params.databaseController || (0, _requiredParameter.default)('You must provide a databaseController instance!');
    this.log = params.log || (0, _requiredParameter.default)('You must provide a log instance!');
    this.graphQLCustomTypeDefs = params.graphQLCustomTypeDefs;
    this.appId = params.appId || (0, _requiredParameter.default)('You must provide the appId!');
    this.schemaCache = _SchemaCache.default;
  }

  async load() {
    const {
      parseGraphQLConfig
    } = await this._initializeSchemaAndConfig();
    const parseClasses = await this._getClassesForSchema(parseGraphQLConfig);
    const parseClassesString = JSON.stringify(parseClasses);
    const functionNames = await this._getFunctionNames();
    const functionNamesString = JSON.stringify(functionNames);

    if (this.graphQLSchema && !this._hasSchemaInputChanged({
      parseClasses,
      parseClassesString,
      parseGraphQLConfig,
      functionNamesString
    })) {
      return this.graphQLSchema;
    }

    this.parseClasses = parseClasses;
    this.parseClassesString = parseClassesString;
    this.parseGraphQLConfig = parseGraphQLConfig;
    this.functionNames = functionNames;
    this.functionNamesString = functionNamesString;
    this.parseClassTypes = {};
    this.viewerType = null;
    this.graphQLAutoSchema = null;
    this.graphQLSchema = null;
    this.graphQLTypes = [];
    this.graphQLQueries = {};
    this.graphQLMutations = {};
    this.graphQLSubscriptions = {};
    this.graphQLSchemaDirectivesDefinitions = null;
    this.graphQLSchemaDirectives = {};
    this.relayNodeInterface = null;
    defaultGraphQLTypes.load(this);
    defaultRelaySchema.load(this);
    schemaTypes.load(this);

    this._getParseClassesWithConfig(parseClasses, parseGraphQLConfig).forEach(([parseClass, parseClassConfig]) => {
      parseClassTypes.load(this, parseClass, parseClassConfig);
      parseClassQueries.load(this, parseClass, parseClassConfig);
      parseClassMutations.load(this, parseClass, parseClassConfig);
    });

    defaultGraphQLTypes.loadArrayResult(this, parseClasses);
    defaultGraphQLQueries.load(this);
    defaultGraphQLMutations.load(this);
    let graphQLQuery = undefined;

    if (Object.keys(this.graphQLQueries).length > 0) {
      graphQLQuery = new _graphql.GraphQLObjectType({
        name: 'Query',
        description: 'Query is the top level type for queries.',
        fields: this.graphQLQueries
      });
      this.addGraphQLType(graphQLQuery, true, true);
    }

    let graphQLMutation = undefined;

    if (Object.keys(this.graphQLMutations).length > 0) {
      graphQLMutation = new _graphql.GraphQLObjectType({
        name: 'Mutation',
        description: 'Mutation is the top level type for mutations.',
        fields: this.graphQLMutations
      });
      this.addGraphQLType(graphQLMutation, true, true);
    }

    let graphQLSubscription = undefined;

    if (Object.keys(this.graphQLSubscriptions).length > 0) {
      graphQLSubscription = new _graphql.GraphQLObjectType({
        name: 'Subscription',
        description: 'Subscription is the top level type for subscriptions.',
        fields: this.graphQLSubscriptions
      });
      this.addGraphQLType(graphQLSubscription, true, true);
    }

    this.graphQLAutoSchema = new _graphql.GraphQLSchema({
      types: this.graphQLTypes,
      query: graphQLQuery,
      mutation: graphQLMutation,
      subscription: graphQLSubscription
    });

    if (this.graphQLCustomTypeDefs) {
      schemaDirectives.load(this);

      if (typeof this.graphQLCustomTypeDefs.getTypeMap === 'function') {
        const customGraphQLSchemaTypeMap = this.graphQLCustomTypeDefs.getTypeMap();

        const findAndReplaceLastType = (parent, key) => {
          if (parent[key].name) {
            if (this.graphQLAutoSchema.getType(parent[key].name) && this.graphQLAutoSchema.getType(parent[key].name) !== parent[key]) {
              // To avoid unresolved field on overloaded schema
              // replace the final type with the auto schema one
              parent[key] = this.graphQLAutoSchema.getType(parent[key].name);
            }
          } else {
            if (parent[key].ofType) {
              findAndReplaceLastType(parent[key], 'ofType');
            }
          }
        };

        Object.values(customGraphQLSchemaTypeMap).forEach(customGraphQLSchemaType => {
          if (!customGraphQLSchemaType || !customGraphQLSchemaType.name || customGraphQLSchemaType.name.startsWith('__')) {
            return;
          }

          const autoGraphQLSchemaType = this.graphQLAutoSchema.getType(customGraphQLSchemaType.name);

          if (!autoGraphQLSchemaType) {
            this.graphQLAutoSchema._typeMap[customGraphQLSchemaType.name] = customGraphQLSchemaType;
          }
        });
        Object.values(customGraphQLSchemaTypeMap).forEach(customGraphQLSchemaType => {
          if (!customGraphQLSchemaType || !customGraphQLSchemaType.name || customGraphQLSchemaType.name.startsWith('__')) {
            return;
          }

          const autoGraphQLSchemaType = this.graphQLAutoSchema.getType(customGraphQLSchemaType.name);

          if (autoGraphQLSchemaType && typeof customGraphQLSchemaType.getFields === 'function') {
            Object.values(customGraphQLSchemaType.getFields()).forEach(field => {
              findAndReplaceLastType(field, 'type');
            });
            autoGraphQLSchemaType._fields = _objectSpread(_objectSpread({}, autoGraphQLSchemaType.getFields()), customGraphQLSchemaType.getFields());
          }
        });
        this.graphQLSchema = (0, _stitch.stitchSchemas)({
          schemas: [this.graphQLSchemaDirectivesDefinitions, this.graphQLAutoSchema],
          mergeDirectives: true
        });
      } else if (typeof this.graphQLCustomTypeDefs === 'function') {
        this.graphQLSchema = await this.graphQLCustomTypeDefs({
          directivesDefinitionsSchema: this.graphQLSchemaDirectivesDefinitions,
          autoSchema: this.graphQLAutoSchema,
          stitchSchemas: _stitch.stitchSchemas
        });
      } else {
        this.graphQLSchema = (0, _stitch.stitchSchemas)({
          schemas: [this.graphQLSchemaDirectivesDefinitions, this.graphQLAutoSchema, this.graphQLCustomTypeDefs],
          mergeDirectives: true
        });
      }

      const graphQLSchemaTypeMap = this.graphQLSchema.getTypeMap();
      Object.keys(graphQLSchemaTypeMap).forEach(graphQLSchemaTypeName => {
        const graphQLSchemaType = graphQLSchemaTypeMap[graphQLSchemaTypeName];

        if (typeof graphQLSchemaType.getFields === 'function' && this.graphQLCustomTypeDefs.definitions) {
          const graphQLCustomTypeDef = this.graphQLCustomTypeDefs.definitions.find(definition => definition.name.value === graphQLSchemaTypeName);

          if (graphQLCustomTypeDef) {
            const graphQLSchemaTypeFieldMap = graphQLSchemaType.getFields();
            Object.keys(graphQLSchemaTypeFieldMap).forEach(graphQLSchemaTypeFieldName => {
              const graphQLSchemaTypeField = graphQLSchemaTypeFieldMap[graphQLSchemaTypeFieldName];

              if (!graphQLSchemaTypeField.astNode) {
                const astNode = graphQLCustomTypeDef.fields.find(field => field.name.value === graphQLSchemaTypeFieldName);

                if (astNode) {
                  graphQLSchemaTypeField.astNode = astNode;
                }
              }
            });
          }
        }
      });

      _utils.SchemaDirectiveVisitor.visitSchemaDirectives(this.graphQLSchema, this.graphQLSchemaDirectives);
    } else {
      this.graphQLSchema = this.graphQLAutoSchema;
    }

    return this.graphQLSchema;
  }

  addGraphQLType(type, throwError = false, ignoreReserved = false, ignoreConnection = false) {
    if (!ignoreReserved && RESERVED_GRAPHQL_TYPE_NAMES.includes(type.name) || this.graphQLTypes.find(existingType => existingType.name === type.name) || !ignoreConnection && type.name.endsWith('Connection')) {
      const message = `Type ${type.name} could not be added to the auto schema because it collided with an existing type.`;

      if (throwError) {
        throw new Error(message);
      }

      this.log.warn(message);
      return undefined;
    }

    this.graphQLTypes.push(type);
    return type;
  }

  addGraphQLQuery(fieldName, field, throwError = false, ignoreReserved = false) {
    if (!ignoreReserved && RESERVED_GRAPHQL_QUERY_NAMES.includes(fieldName) || this.graphQLQueries[fieldName]) {
      const message = `Query ${fieldName} could not be added to the auto schema because it collided with an existing field.`;

      if (throwError) {
        throw new Error(message);
      }

      this.log.warn(message);
      return undefined;
    }

    this.graphQLQueries[fieldName] = field;
    return field;
  }

  addGraphQLMutation(fieldName, field, throwError = false, ignoreReserved = false) {
    if (!ignoreReserved && RESERVED_GRAPHQL_MUTATION_NAMES.includes(fieldName) || this.graphQLMutations[fieldName]) {
      const message = `Mutation ${fieldName} could not be added to the auto schema because it collided with an existing field.`;

      if (throwError) {
        throw new Error(message);
      }

      this.log.warn(message);
      return undefined;
    }

    this.graphQLMutations[fieldName] = field;
    return field;
  }

  handleError(error) {
    if (error instanceof _node.default.Error) {
      this.log.error('Parse error: ', error);
    } else {
      this.log.error('Uncaught internal server error.', error, error.stack);
    }

    throw (0, _parseGraphQLUtils.toGraphQLError)(error);
  }

  async _initializeSchemaAndConfig() {
    const [schemaController, parseGraphQLConfig] = await Promise.all([this.databaseController.loadSchema(), this.parseGraphQLController.getGraphQLConfig()]);
    this.schemaController = schemaController;
    return {
      parseGraphQLConfig
    };
  }
  /**
   * Gets all classes found by the `schemaController`
   * minus those filtered out by the app's parseGraphQLConfig.
   */


  async _getClassesForSchema(parseGraphQLConfig) {
    const {
      enabledForClasses,
      disabledForClasses
    } = parseGraphQLConfig;
    const allClasses = await this.schemaController.getAllClasses();

    if (Array.isArray(enabledForClasses) || Array.isArray(disabledForClasses)) {
      let includedClasses = allClasses;

      if (enabledForClasses) {
        includedClasses = allClasses.filter(clazz => {
          return enabledForClasses.includes(clazz.className);
        });
      }

      if (disabledForClasses) {
        // Classes included in `enabledForClasses` that
        // are also present in `disabledForClasses` will
        // still be filtered out
        includedClasses = includedClasses.filter(clazz => {
          return !disabledForClasses.includes(clazz.className);
        });
      }

      this.isUsersClassDisabled = !includedClasses.some(clazz => {
        return clazz.className === '_User';
      });
      return includedClasses;
    } else {
      return allClasses;
    }
  }
  /**
   * This method returns a list of tuples
   * that provide the parseClass along with
   * its parseClassConfig where provided.
   */


  _getParseClassesWithConfig(parseClasses, parseGraphQLConfig) {
    const {
      classConfigs
    } = parseGraphQLConfig; // Make sures that the default classes and classes that
    // starts with capitalized letter will be generated first.

    const sortClasses = (a, b) => {
      a = a.className;
      b = b.className;

      if (a[0] === '_') {
        if (b[0] !== '_') {
          return -1;
        }
      }

      if (b[0] === '_') {
        if (a[0] !== '_') {
          return 1;
        }
      }

      if (a === b) {
        return 0;
      } else if (a < b) {
        return -1;
      } else {
        return 1;
      }
    };

    return parseClasses.sort(sortClasses).map(parseClass => {
      let parseClassConfig;

      if (classConfigs) {
        parseClassConfig = classConfigs.find(c => c.className === parseClass.className);
      }

      return [parseClass, parseClassConfig];
    });
  }

  async _getFunctionNames() {
    return await (0, _triggers.getFunctionNames)(this.appId).filter(functionName => {
      if (/^[_a-zA-Z][_a-zA-Z0-9]*$/.test(functionName)) {
        return true;
      } else {
        this.log.warn(`Function ${functionName} could not be added to the auto schema because GraphQL names must match /^[_a-zA-Z][_a-zA-Z0-9]*$/.`);
        return false;
      }
    });
  }
  /**
   * Checks for changes to the parseClasses
   * objects (i.e. database schema) or to
   * the parseGraphQLConfig object. If no
   * changes are found, return true;
   */


  _hasSchemaInputChanged(params) {
    const {
      parseClasses,
      parseClassesString,
      parseGraphQLConfig,
      functionNamesString
    } = params;

    if (JSON.stringify(this.parseGraphQLConfig) === JSON.stringify(parseGraphQLConfig) && this.functionNamesString === functionNamesString) {
      if (this.parseClasses === parseClasses) {
        return false;
      }

      if (this.parseClassesString === parseClassesString) {
        this.parseClasses = parseClasses;
        return false;
      }
    }

    return true;
  }

}

exports.ParseGraphQLSchema = ParseGraphQLSchema;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9HcmFwaFFML1BhcnNlR3JhcGhRTFNjaGVtYS5qcyJdLCJuYW1lcyI6WyJSRVNFUlZFRF9HUkFQSFFMX1RZUEVfTkFNRVMiLCJSRVNFUlZFRF9HUkFQSFFMX1FVRVJZX05BTUVTIiwiUkVTRVJWRURfR1JBUEhRTF9NVVRBVElPTl9OQU1FUyIsIlBhcnNlR3JhcGhRTFNjaGVtYSIsImNvbnN0cnVjdG9yIiwicGFyYW1zIiwicGFyc2VHcmFwaFFMQ29udHJvbGxlciIsImRhdGFiYXNlQ29udHJvbGxlciIsImxvZyIsImdyYXBoUUxDdXN0b21UeXBlRGVmcyIsImFwcElkIiwic2NoZW1hQ2FjaGUiLCJTY2hlbWFDYWNoZSIsImxvYWQiLCJwYXJzZUdyYXBoUUxDb25maWciLCJfaW5pdGlhbGl6ZVNjaGVtYUFuZENvbmZpZyIsInBhcnNlQ2xhc3NlcyIsIl9nZXRDbGFzc2VzRm9yU2NoZW1hIiwicGFyc2VDbGFzc2VzU3RyaW5nIiwiSlNPTiIsInN0cmluZ2lmeSIsImZ1bmN0aW9uTmFtZXMiLCJfZ2V0RnVuY3Rpb25OYW1lcyIsImZ1bmN0aW9uTmFtZXNTdHJpbmciLCJncmFwaFFMU2NoZW1hIiwiX2hhc1NjaGVtYUlucHV0Q2hhbmdlZCIsInBhcnNlQ2xhc3NUeXBlcyIsInZpZXdlclR5cGUiLCJncmFwaFFMQXV0b1NjaGVtYSIsImdyYXBoUUxUeXBlcyIsImdyYXBoUUxRdWVyaWVzIiwiZ3JhcGhRTE11dGF0aW9ucyIsImdyYXBoUUxTdWJzY3JpcHRpb25zIiwiZ3JhcGhRTFNjaGVtYURpcmVjdGl2ZXNEZWZpbml0aW9ucyIsImdyYXBoUUxTY2hlbWFEaXJlY3RpdmVzIiwicmVsYXlOb2RlSW50ZXJmYWNlIiwiZGVmYXVsdEdyYXBoUUxUeXBlcyIsImRlZmF1bHRSZWxheVNjaGVtYSIsInNjaGVtYVR5cGVzIiwiX2dldFBhcnNlQ2xhc3Nlc1dpdGhDb25maWciLCJmb3JFYWNoIiwicGFyc2VDbGFzcyIsInBhcnNlQ2xhc3NDb25maWciLCJwYXJzZUNsYXNzUXVlcmllcyIsInBhcnNlQ2xhc3NNdXRhdGlvbnMiLCJsb2FkQXJyYXlSZXN1bHQiLCJkZWZhdWx0R3JhcGhRTFF1ZXJpZXMiLCJkZWZhdWx0R3JhcGhRTE11dGF0aW9ucyIsImdyYXBoUUxRdWVyeSIsInVuZGVmaW5lZCIsIk9iamVjdCIsImtleXMiLCJsZW5ndGgiLCJHcmFwaFFMT2JqZWN0VHlwZSIsIm5hbWUiLCJkZXNjcmlwdGlvbiIsImZpZWxkcyIsImFkZEdyYXBoUUxUeXBlIiwiZ3JhcGhRTE11dGF0aW9uIiwiZ3JhcGhRTFN1YnNjcmlwdGlvbiIsIkdyYXBoUUxTY2hlbWEiLCJ0eXBlcyIsInF1ZXJ5IiwibXV0YXRpb24iLCJzdWJzY3JpcHRpb24iLCJzY2hlbWFEaXJlY3RpdmVzIiwiZ2V0VHlwZU1hcCIsImN1c3RvbUdyYXBoUUxTY2hlbWFUeXBlTWFwIiwiZmluZEFuZFJlcGxhY2VMYXN0VHlwZSIsInBhcmVudCIsImtleSIsImdldFR5cGUiLCJvZlR5cGUiLCJ2YWx1ZXMiLCJjdXN0b21HcmFwaFFMU2NoZW1hVHlwZSIsInN0YXJ0c1dpdGgiLCJhdXRvR3JhcGhRTFNjaGVtYVR5cGUiLCJfdHlwZU1hcCIsImdldEZpZWxkcyIsImZpZWxkIiwiX2ZpZWxkcyIsInNjaGVtYXMiLCJtZXJnZURpcmVjdGl2ZXMiLCJkaXJlY3RpdmVzRGVmaW5pdGlvbnNTY2hlbWEiLCJhdXRvU2NoZW1hIiwic3RpdGNoU2NoZW1hcyIsImdyYXBoUUxTY2hlbWFUeXBlTWFwIiwiZ3JhcGhRTFNjaGVtYVR5cGVOYW1lIiwiZ3JhcGhRTFNjaGVtYVR5cGUiLCJkZWZpbml0aW9ucyIsImdyYXBoUUxDdXN0b21UeXBlRGVmIiwiZmluZCIsImRlZmluaXRpb24iLCJ2YWx1ZSIsImdyYXBoUUxTY2hlbWFUeXBlRmllbGRNYXAiLCJncmFwaFFMU2NoZW1hVHlwZUZpZWxkTmFtZSIsImdyYXBoUUxTY2hlbWFUeXBlRmllbGQiLCJhc3ROb2RlIiwiU2NoZW1hRGlyZWN0aXZlVmlzaXRvciIsInZpc2l0U2NoZW1hRGlyZWN0aXZlcyIsInR5cGUiLCJ0aHJvd0Vycm9yIiwiaWdub3JlUmVzZXJ2ZWQiLCJpZ25vcmVDb25uZWN0aW9uIiwiaW5jbHVkZXMiLCJleGlzdGluZ1R5cGUiLCJlbmRzV2l0aCIsIm1lc3NhZ2UiLCJFcnJvciIsIndhcm4iLCJwdXNoIiwiYWRkR3JhcGhRTFF1ZXJ5IiwiZmllbGROYW1lIiwiYWRkR3JhcGhRTE11dGF0aW9uIiwiaGFuZGxlRXJyb3IiLCJlcnJvciIsIlBhcnNlIiwic3RhY2siLCJzY2hlbWFDb250cm9sbGVyIiwiUHJvbWlzZSIsImFsbCIsImxvYWRTY2hlbWEiLCJnZXRHcmFwaFFMQ29uZmlnIiwiZW5hYmxlZEZvckNsYXNzZXMiLCJkaXNhYmxlZEZvckNsYXNzZXMiLCJhbGxDbGFzc2VzIiwiZ2V0QWxsQ2xhc3NlcyIsIkFycmF5IiwiaXNBcnJheSIsImluY2x1ZGVkQ2xhc3NlcyIsImZpbHRlciIsImNsYXp6IiwiY2xhc3NOYW1lIiwiaXNVc2Vyc0NsYXNzRGlzYWJsZWQiLCJzb21lIiwiY2xhc3NDb25maWdzIiwic29ydENsYXNzZXMiLCJhIiwiYiIsInNvcnQiLCJtYXAiLCJjIiwiZnVuY3Rpb25OYW1lIiwidGVzdCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOzs7Ozs7Ozs7Ozs7OztBQUVBLE1BQU1BLDJCQUEyQixHQUFHLENBQ2xDLFFBRGtDLEVBRWxDLFNBRmtDLEVBR2xDLEtBSGtDLEVBSWxDLE9BSmtDLEVBS2xDLElBTGtDLEVBTWxDLGFBTmtDLEVBT2xDLE9BUGtDLEVBUWxDLFVBUmtDLEVBU2xDLGNBVGtDLEVBVWxDLGlCQVZrQyxFQVdsQyxtQkFYa0MsRUFZbEMsUUFaa0MsRUFhbEMsYUFia0MsRUFjbEMsZUFka0MsRUFlbEMsWUFma0MsRUFnQmxDLGNB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VCxDQUNHLFlBQVdpQyxZQUFhLHFHQUQzQjtBQUdBLGVBQU8sS0FBUDtBQUNEO0FBQ0YsS0FUWSxDQUFiO0FBVUQ7QUFFRDtBQUNGO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7OztBQUNFckgsRUFBQUEsc0JBQXNCLENBQUNwQixNQUFELEVBS1Y7QUFDVixVQUFNO0FBQUVXLE1BQUFBLFlBQUY7QUFBZ0JFLE1BQUFBLGtCQUFoQjtBQUFvQ0osTUFBQUEsa0JBQXBDO0FBQXdEUyxNQUFBQTtBQUF4RCxRQUFnRmxCLE1BQXRGOztBQUVBLFFBQ0VjLElBQUksQ0FBQ0MsU0FBTCxDQUFlLEtBQUtOLGtCQUFwQixNQUE0Q0ssSUFBSSxDQUFDQyxTQUFMLENBQWVOLGtCQUFmLENBQTVDLElBQ0EsS0FBS1MsbUJBQUwsS0FBNkJBLG1CQUYvQixFQUdFO0FBQ0EsVUFBSSxLQUFLUCxZQUFMLEtBQXNCQSxZQUExQixFQUF3QztBQUN0QyxlQUFPLEtBQVA7QUFDRDs7QUFFRCxVQUFJLEtBQUtFLGtCQUFMLEtBQTRCQSxrQkFBaEMsRUFBb0Q7QUFDbEQsYUFBS0YsWUFBTCxHQUFvQkEsWUFBcEI7QUFDQSxlQUFPLEtBQVA7QUFDRDtBQUNGOztBQUVELFdBQU8sSUFBUDtBQUNEOztBQXhhc0IiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgUGFyc2UgZnJvbSAncGFyc2Uvbm9kZSc7XG5pbXBvcnQgeyBHcmFwaFFMU2NoZW1hLCBHcmFwaFFMT2JqZWN0VHlwZSwgRG9jdW1lbnROb2RlLCBHcmFwaFFMTmFtZWRUeXBlIH0gZnJvbSAnZ3JhcGhxbCc7XG5pbXBvcnQgeyBzdGl0Y2hTY2hlbWFzIH0gZnJvbSAnQGdyYXBocWwtdG9vbHMvc3RpdGNoJztcbmltcG9ydCB7IFNjaGVtYURpcmVjdGl2ZVZpc2l0b3IgfSBmcm9tICdAZ3JhcGhxbC10b29scy91dGlscyc7XG5pbXBvcnQgcmVxdWlyZWRQYXJhbWV0ZXIgZnJvbSAnLi4vcmVxdWlyZWRQYXJhbWV0ZXInO1xuaW1wb3J0ICogYXMgZGVmYXVsdEdyYXBoUUxUeXBlcyBmcm9tICcuL2xvYWRlcnMvZGVmYXVsdEdyYXBoUUxUeXBlcyc7XG5pbXBvcnQgKiBhcyBwYXJzZUNsYXNzVHlwZXMgZnJvbSAnLi9sb2FkZXJzL3BhcnNlQ2xhc3NUeXBlcyc7XG5pbXBvcnQgKiBhcyBwYXJzZUNsYXNzUXVlcmllcyBmcm9tICcuL2xvYWRlcnMvcGFyc2VDbGFzc1F1ZXJpZXMnO1xuaW1wb3J0ICogYXMgcGFyc2VDbGFzc011dGF0aW9ucyBmcm9tICcuL2xvYWRlcnMvcGFyc2VDbGFzc011dGF0aW9ucyc7XG5pbXBvcnQgKiBhcyBkZWZhdWx0R3JhcGhRTFF1ZXJpZXMgZnJvbSAnLi9sb2FkZXJzL2RlZmF1bHRHcmFwaFFMUXVlcmllcyc7XG5pbXBvcnQgKiBhcyBkZWZhdWx0R3JhcGhRTE11dGF0aW9ucyBmcm9tICcuL2xvYWRlcnMvZGVmYXVsdEdyYXBoUUxNdXRhdGlvbnMnO1xuaW1wb3J0IFBhcnNlR3JhcGhRTENvbnRyb2xsZXIsIHsgUGFyc2VHcmFwaFFMQ29uZmlnIH0gZnJvbSAnLi4vQ29udHJvbGxlcnMvUGFyc2VHcmFwaFFMQ29udHJvbGxlcic7XG5pbXBvcnQgRGF0YWJhc2VDb250cm9sbGVyIGZyb20gJy4uL0NvbnRyb2xsZXJzL0RhdGFiYXNlQ29udHJvbGxlcic7XG5pbXBvcnQgU2NoZW1hQ2FjaGUgZnJvbSAnLi4vQWRhcHRlcnMvQ2FjaGUvU2NoZW1hQ2FjaGUnO1xuaW1wb3J0IHsgdG9HcmFwaFFMRXJyb3IgfSBmcm9tICcuL3BhcnNlR3JhcGhRTFV0aWxzJztcbmltcG9ydCAqIGFzIHNjaGVtYURpcmVjdGl2ZXMgZnJvbSAnLi9sb2FkZXJzL3NjaGVtYURpcmVjdGl2ZXMnO1xuaW1wb3J0ICogYXMgc2NoZW1hVHlwZXMgZnJvbSAnLi9sb2FkZXJzL3NjaGVtYVR5cGVzJztcbmltcG9ydCB7IGdldEZ1bmN0aW9uTmFtZXMgfSBmcm9tICcuLi90cmlnZ2Vycyc7XG5pbXBvcnQgKiBhcyBkZWZhdWx0UmVsYXlTY2hlbWEgZnJvbSAnLi9sb2FkZXJzL2RlZmF1bHRSZWxheVNjaGVtYSc7XG5cbmNvbnN0IFJFU0VSVkVEX0dSQVBIUUxfVFlQRV9OQU1FUyA9IFtcbiAgJ1N0cmluZycsXG4gICdCb29sZWFuJyxcbiAgJ0ludCcsXG4gICdGbG9hdCcsXG4gICdJRCcsXG4gICdBcnJheVJlc3VsdCcsXG4gICdRdWVyeScsXG4gICdNdXRhdGlvbicsXG4gICdTdWJzY3JpcHRpb24nLFxuICAnQ3JlYXRlRmlsZUlucHV0JyxcbiAgJ0NyZWF0ZUZpbGVQYXlsb2FkJyxcbiAgJ1ZpZXdlcicsXG4gICdTaWduVXBJbnB1dCcsXG4gICdTaWduVXBQYXlsb2FkJyxcbiAgJ0xvZ0luSW5wdXQnLFxuICAnTG9nSW5QYXlsb2FkJyxcbiAgJ0xvZ091dElucHV0JyxcbiAgJ0xvZ091dFBheWxvYWQnLFxuICAnQ2xvdWRDb2RlRnVuY3Rpb24nLFxuICAnQ2FsbENsb3VkQ29kZUlucHV0JyxcbiAgJ0NhbGxDbG91ZENvZGVQYXlsb2FkJyxcbiAgJ0NyZWF0ZUNsYXNzSW5wdXQnLFxuICAnQ3JlYXRlQ2xhc3NQYXlsb2FkJyxcbiAgJ1VwZGF0ZUNsYXNzSW5wdXQnLFxuICAnVXBkYXRlQ2xhc3NQYXlsb2FkJyxcbiAgJ0RlbGV0ZUNsYXNzSW5wdXQnLFxuICAnRGVsZXRlQ2xhc3NQYXlsb2FkJyxcbiAgJ1BhZ2VJbmZvJyxcbl07XG5jb25zdCBSRVNFUlZFRF9HUkFQSFFMX1FVRVJZX05BTUVTID0gWydoZWFsdGgnLCAndmlld2VyJywgJ2NsYXNzJywgJ2NsYXNzZXMnXTtcbmNvbnN0IFJFU0VSVkVEX0dSQVBIUUxfTVVUQVRJT05fTkFNRVMgPSBbXG4gICdzaWduVXAnLFxuICAnbG9nSW4nLFxuICAnbG9nT3V0JyxcbiAgJ2NyZWF0ZUZpbGUnLFxuICAnY2FsbENsb3VkQ29kZScsXG4gICdjcmVhdGVDbGFzcycsXG4gICd1cGRhdGVDbGFzcycsXG4gICdkZWxldGVDbGFzcycsXG5dO1xuXG5jbGFzcyBQYXJzZUdyYXBoUUxTY2hlbWEge1xuICBkYXRhYmFzZUNvbnRyb2xsZXI6IERhdGFiYXNlQ29udHJvbGxlcjtcbiAgcGFyc2VHcmFwaFFMQ29udHJvbGxlcjogUGFyc2VHcmFwaFFMQ29udHJvbGxlcjtcbiAgcGFyc2VHcmFwaFFMQ29uZmlnOiBQYXJzZUdyYXBoUUxDb25maWc7XG4gIGxvZzogYW55O1xuICBhcHBJZDogc3RyaW5nO1xuICBncmFwaFFMQ3VzdG9tVHlwZURlZnM6ID8oc3RyaW5nIHwgR3JhcGhRTFNjaGVtYSB8IERvY3VtZW50Tm9kZSB8IEdyYXBoUUxOYW1lZFR5cGVbXSk7XG4gIHNjaGVtYUNhY2hlOiBhbnk7XG5cbiAgY29uc3RydWN0b3IoXG4gICAgcGFyYW1zOiB7XG4gICAgICBkYXRhYmFzZUNvbnRyb2xsZXI6IERhdGFiYXNlQ29udHJvbGxlcixcbiAgICAgIHBhcnNlR3JhcGhRTENvbnRyb2xsZXI6IFBhcnNlR3JhcGhRTENvbnRyb2xsZXIsXG4gICAgICBsb2c6IGFueSxcbiAgICAgIGFwcElkOiBzdHJpbmcsXG4gICAgICBncmFwaFFMQ3VzdG9tVHlwZURlZnM6ID8oc3RyaW5nIHwgR3JhcGhRTFNjaGVtYSB8IERvY3VtZW50Tm9kZSB8IEdyYXBoUUxOYW1lZFR5cGVbXSksXG4gICAgfSA9IHt9XG4gICkge1xuICAgIHRoaXMucGFyc2VHcmFwaFFMQ29udHJvbGxlciA9XG4gICAgICBwYXJhbXMucGFyc2VHcmFwaFFMQ29udHJvbGxlciB8fFxuICAgICAgcmVxdWlyZWRQYXJhbWV0ZXIoJ1lvdSBtdXN0IHByb3ZpZGUgYSBwYXJzZUdyYXBoUUxDb250cm9sbGVyIGluc3RhbmNlIScpO1xuICAgIHRoaXMuZGF0YWJhc2VDb250cm9sbGVyID1cbiAgICAgIHBhcmFtcy5kYXRhYmFzZUNvbnRyb2xsZXIgfHxcbiAgICAgIHJlcXVpcmVkUGFyYW1ldGVyKCdZb3UgbXVzdCBwcm92aWRlIGEgZGF0YWJhc2VDb250cm9sbGVyIGluc3RhbmNlIScpO1xuICAgIHRoaXMubG9nID0gcGFyYW1zLmxvZyB8fCByZXF1aXJlZFBhcmFtZXRlcignWW91IG11c3QgcHJvdmlkZSBhIGxvZyBpbnN0YW5jZSEnKTtcbiAgICB0aGlzLmdyYXBoUUxDdXN0b21UeXBlRGVmcyA9IHBhcmFtcy5ncmFwaFFMQ3VzdG9tVHlwZURlZnM7XG4gICAgdGhpcy5hcHBJZCA9IHBhcmFtcy5hcHBJZCB8fCByZXF1aXJlZFBhcmFtZXRlcignWW91IG11c3QgcHJvdmlkZSB0aGUgYXBwSWQhJyk7XG4gICAgdGhpcy5zY2hlbWFDYWNoZSA9IFNjaGVtYUNhY2hlO1xuICB9XG5cbiAgYXN5bmMgbG9hZCgpIHtcbiAgICBjb25zdCB7IHBhcnNlR3JhcGhRTENvbmZpZyB9ID0gYXdhaXQgdGhpcy5faW5pdGlhbGl6ZVNjaGVtYUFuZENvbmZpZygpO1xuICAgIGNvbnN0IHBhcnNlQ2xhc3NlcyA9IGF3YWl0IHRoaXMuX2dldENsYXNzZXNGb3JTY2hlbWEocGFyc2VHcmFwaFFMQ29uZmlnKTtcbiAgICBjb25zdCBwYXJzZUNsYXNzZXNTdHJpbmcgPSBKU09OLnN0cmluZ2lmeShwYXJzZUNsYXNzZXMpO1xuICAgIGNvbnN0IGZ1bmN0aW9uTmFtZXMgPSBhd2FpdCB0aGlzLl9nZXRGdW5jdGlvbk5hbWVzKCk7XG4gICAgY29uc3QgZnVuY3Rpb25OYW1lc1N0cmluZyA9IEpTT04uc3RyaW5naWZ5KGZ1bmN0aW9uTmFtZXMpO1xuXG4gICAgaWYgKFxuICAgICAgdGhpcy5ncmFwaFFMU2NoZW1hICYmXG4gICAgICAhdGhpcy5faGFzU2NoZW1hSW5wdXRDaGFuZ2VkKHtcbiAgICAgICAgcGFyc2VDbGFzc2VzLFxuICAgICAgICBwYXJzZUNsYXNzZXNTdHJpbmcsXG4gICAgICAgIHBhcnNlR3JhcGhRTENvbmZpZyxcbiAgICAgICAgZnVuY3Rpb25OYW1lc1N0cmluZyxcbiAgICAgIH0pXG4gICAgKSB7XG4gICAgICByZXR1cm4gdGhpcy5ncmFwaFFMU2NoZW1hO1xuICAgIH1cblxuICAgIHRoaXMucGFyc2VDbGFzc2VzID0gcGFyc2VDbGFzc2VzO1xuICAgIHRoaXMucGFyc2VDbGFzc2VzU3RyaW5nID0gcGFyc2VDbGFzc2VzU3RyaW5nO1xuICAgIHRoaXMucGFyc2VHcmFwaFFMQ29uZmlnID0gcGFyc2VHcmFwaFFMQ29uZmlnO1xuICAgIHRoaXMuZnVuY3Rpb25OYW1lcyA9IGZ1bmN0aW9uTmFtZXM7XG4gICAgdGhpcy5mdW5jdGlvbk5hbWVzU3RyaW5nID0gZnVuY3Rpb25OYW1lc1N0cmluZztcbiAgICB0aGlzLnBhcnNlQ2xhc3NUeXBlcyA9IHt9O1xuICAgIHRoaXMudmlld2VyVHlwZSA9IG51bGw7XG4gICAgdGhpcy5ncmFwaFFMQXV0b1NjaGVtYSA9IG51bGw7XG4gICAgdGhpcy5ncmFwaFFMU2NoZW1hID0gbnVsbDtcbiAgICB0aGlzLmdyYXBoUUxUeXBlcyA9IFtdO1xuICAgIHRoaXMuZ3JhcGhRTFF1ZXJpZXMgPSB7fTtcbiAgICB0aGlzLmdyYXBoUUxNdXRhdGlvbnMgPSB7fTtcbiAgICB0aGlzLmdyYXBoUUxTdWJzY3JpcHRpb25zID0ge307XG4gICAgdGhpcy5ncmFwaFFMU2NoZW1hRGlyZWN0aXZlc0RlZmluaXRpb25zID0gbnVsbDtcbiAgICB0aGlzLmdyYXBoUUxTY2hlbWFEaXJlY3RpdmVzID0ge307XG4gICAgdGhpcy5yZWxheU5vZGVJbnRlcmZhY2UgPSBudWxsO1xuXG4gICAgZGVmYXVsdEdyYXBoUUxUeXBlcy5sb2FkKHRoaXMpO1xuICAgIGRlZmF1bHRSZWxheVNjaGVtYS5sb2FkKHRoaXMpO1xuICAgIHNjaGVtYVR5cGVzLmxvYWQodGhpcyk7XG5cbiAgICB0aGlzLl9nZXRQYXJzZUNsYXNzZXNXaXRoQ29uZmlnKHBhcnNlQ2xhc3NlcywgcGFyc2VHcmFwaFFMQ29uZmlnKS5mb3JFYWNoKFxuICAgICAgKFtwYXJzZUNsYXNzLCBwYXJzZUNsYXNzQ29uZmlnXSkgPT4ge1xuICAgICAgICBwYXJzZUNsYXNzVHlwZXMubG9hZCh0aGlzLCBwYXJzZUNsYXNzLCBwYXJzZUNsYXNzQ29uZmlnKTtcbiAgICAgICAgcGFyc2VDbGFzc1F1ZXJpZXMubG9hZCh0aGlzLCBwYXJzZUNsYXNzLCBwYXJzZUNsYXNzQ29uZmlnKTtcbiAgICAgICAgcGFyc2VDbGFzc011dGF0aW9ucy5sb2FkKHRoaXMsIHBhcnNlQ2xhc3MsIHBhcnNlQ2xhc3NDb25maWcpO1xuICAgICAgfVxuICAgICk7XG5cbiAgICBkZWZhdWx0R3JhcGhRTFR5cGVzLmxvYWRBcnJheVJlc3VsdCh0aGlzLCBwYXJzZUNsYXNzZXMpO1xuICAgIGRlZmF1bHRHcmFwaFFMUXVlcmllcy5sb2FkKHRoaXMpO1xuICAgIGRlZmF1bHRHcmFwaFFMTXV0YXRpb25zLmxvYWQodGhpcyk7XG5cbiAgICBsZXQgZ3JhcGhRTFF1ZXJ5ID0gdW5kZWZpbmVkO1xuICAgIGlmIChPYmplY3Qua2V5cyh0aGlzLmdyYXBoUUxRdWVyaWVzKS5sZW5ndGggPiAwKSB7XG4gICAgICBncmFwaFFMUXVlcnkgPSBuZXcgR3JhcGhRTE9iamVjdFR5cGUoe1xuICAgICAgICBuYW1lOiAnUXVlcnknLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ1F1ZXJ5IGlzIHRoZSB0b3AgbGV2ZWwgdHlwZSBmb3IgcXVlcmllcy4nLFxuICAgICAgICBmaWVsZHM6IHRoaXMuZ3JhcGhRTFF1ZXJpZXMsXG4gICAgICB9KTtcbiAgICAgIHRoaXMuYWRkR3JhcGhRTFR5cGUoZ3JhcGhRTFF1ZXJ5LCB0cnVlLCB0cnVlKTtcbiAgICB9XG5cbiAgICBsZXQgZ3JhcGhRTE11dGF0aW9uID0gdW5kZWZpbmVkO1xuICAgIGlmIChPYmplY3Qua2V5cyh0aGlzLmdyYXBoUUxNdXRhdGlvbnMpLmxlbmd0aCA+IDApIHtcbiAgICAgIGdyYXBoUUxNdXRhdGlvbiA9IG5ldyBHcmFwaFFMT2JqZWN0VHlwZSh7XG4gICAgICAgIG5hbWU6ICdNdXRhdGlvbicsXG4gICAgICAgIGRlc2NyaXB0aW9uOiAnTXV0YXRpb24gaXMgdGhlIHRvcCBsZXZlbCB0eXBlIGZvciBtdXRhdGlvbnMuJyxcbiAgICAgICAgZmllbGRzOiB0aGlzLmdyYXBoUUxNdXRhdGlvbnMsXG4gICAgICB9KTtcbiAgICAgIHRoaXMuYWRkR3JhcGhRTFR5cGUoZ3JhcGhRTE11dGF0aW9uLCB0cnVlLCB0cnVlKTtcbiAgICB9XG5cbiAgICBsZXQgZ3JhcGhRTFN1YnNjcmlwdGlvbiA9IHVuZGVmaW5lZDtcbiAgICBpZiAoT2JqZWN0LmtleXModGhpcy5ncmFwaFFMU3Vic2NyaXB0aW9ucykubGVuZ3RoID4gMCkge1xuICAgICAgZ3JhcGhRTFN1YnNjcmlwdGlvbiA9IG5ldyBHcmFwaFFMT2JqZWN0VHlwZSh7XG4gICAgICAgIG5hbWU6ICdTdWJzY3JpcHRpb24nLFxuICAgICAgICBkZXNjcmlwdGlvbjogJ1N1YnNjcmlwdGlvbiBpcyB0aGUgdG9wIGxldmVsIHR5cGUgZm9yIHN1YnNjcmlwdGlvbnMuJyxcbiAgICAgICAgZmllbGRzOiB0aGlzLmdyYXBoUUxTdWJzY3JpcHRpb25zLFxuICAgICAgfSk7XG4gICAgICB0aGlzLmFkZEdyYXBoUUxUeXBlKGdyYXBoUUxTdWJzY3JpcHRpb24sIHRydWUsIHRydWUpO1xuICAgIH1cblxuICAgIHRoaXMuZ3JhcGhRTEF1dG9TY2hlbWEgPSBuZXcgR3JhcGhRTFNjaGVtYSh7XG4gICAgICB0eXBlczogdGhpcy5ncmFwaFFMVHlwZXMsXG4gICAgICBxdWVyeTogZ3JhcGhRTFF1ZXJ5LFxuICAgICAgbXV0YXRpb246IGdyYXBoUUxNdXRhdGlvbixcbiAgICAgIHN1YnNjcmlwdGlvbjogZ3JhcGhRTFN1YnNjcmlwdGlvbixcbiAgICB9KTtcblxuICAgIGlmICh0aGlzLmdyYXBoUUxDdXN0b21UeXBlRGVmcykge1xuICAgICAgc2NoZW1hRGlyZWN0aXZlcy5sb2FkKHRoaXMpO1xuXG4gICAgICBpZiAodHlwZW9mIHRoaXMuZ3JhcGhRTEN1c3RvbVR5cGVEZWZzLmdldFR5cGVNYXAgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgY29uc3QgY3VzdG9tR3JhcGhRTFNjaGVtYVR5cGVNYXAgPSB0aGlzLmdyYXBoUUxDdXN0b21UeXBlRGVmcy5nZXRUeXBlTWFwKCk7XG4gICAgICAgIGNvbnN0IGZpbmRBbmRSZXBsYWNlTGFzdFR5cGUgPSAocGFyZW50LCBrZXkpID0+IHtcbiAgICAgICAgICBpZiAocGFyZW50W2tleV0ubmFtZSkge1xuICAgICAgICAgICAgaWYgKFxuICAgICAgICAgICAgICB0aGlzLmdyYXBoUUxBdXRvU2NoZW1hLmdldFR5cGUocGFyZW50W2tleV0ubmFtZSkgJiZcbiAgICAgICAgICAgICAgdGhpcy5ncmFwaFFMQXV0b1NjaGVtYS5nZXRUeXBlKHBhcmVudFtrZXldLm5hbWUpICE9PSBwYXJlbnRba2V5XVxuICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgIC8vIFRvIGF2b2lkIHVucmVzb2x2ZWQgZmllbGQgb24gb3ZlcmxvYWRlZCBzY2hlbWFcbiAgICAgICAgICAgICAgLy8gcmVwbGFjZSB0aGUgZmluYWwgdHlwZSB3aXRoIHRoZSBhdXRvIHNjaGVtYSBvbmVcbiAgICAgICAgICAgICAgcGFyZW50W2tleV0gPSB0aGlzLmdyYXBoUUxBdXRvU2NoZW1hLmdldFR5cGUocGFyZW50W2tleV0ubmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGlmIChwYXJlbnRba2V5XS5vZlR5cGUpIHtcbiAgICAgICAgICAgICAgZmluZEFuZFJlcGxhY2VMYXN0VHlwZShwYXJlbnRba2V5XSwgJ29mVHlwZScpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICAgICAgT2JqZWN0LnZhbHVlcyhjdXN0b21HcmFwaFFMU2NoZW1hVHlwZU1hcCkuZm9yRWFjaChjdXN0b21HcmFwaFFMU2NoZW1hVHlwZSA9PiB7XG4gICAgICAgICAgaWYgKFxuICAgICAgICAgICAgIWN1c3RvbUdyYXBoUUxTY2hlbWFUeXBlIHx8XG4gICAgICAgICAgICAhY3VzdG9tR3JhcGhRTFNjaGVtYVR5cGUubmFtZSB8fFxuICAgICAgICAgICAgY3VzdG9tR3JhcGhRTFNjaGVtYVR5cGUubmFtZS5zdGFydHNXaXRoKCdfXycpXG4gICAgICAgICAgKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuICAgICAgICAgIGNvbnN0IGF1dG9HcmFwaFFMU2NoZW1hVHlwZSA9IHRoaXMuZ3JhcGhRTEF1dG9TY2hlbWEuZ2V0VHlwZShcbiAgICAgICAgICAgIGN1c3RvbUdyYXBoUUxTY2hlbWFUeXBlLm5hbWVcbiAgICAgICAgICApO1xuICAgICAgICAgIGlmICghYXV0b0dyYXBoUUxTY2hlbWFUeXBlKSB7XG4gICAgICAgICAgICB0aGlzLmdyYXBoUUxBdXRvU2NoZW1hLl90eXBlTWFwW2N1c3RvbUdyYXBoUUxTY2hlbWFUeXBlLm5hbWVdID0gY3VzdG9tR3JhcGhRTFNjaGVtYVR5cGU7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgICAgT2JqZWN0LnZhbHVlcyhjdXN0b21HcmFwaFFMU2NoZW1hVHlwZU1hcCkuZm9yRWFjaChjdXN0b21HcmFwaFFMU2NoZW1hVHlwZSA9PiB7XG4gICAgICAgICAgaWYgKFxuICAgICAgICAgICAgIWN1c3RvbUdyYXBoUUxTY2hlbWFUeXBlIHx8XG4gICAgICAgICAgICAhY3VzdG9tR3JhcGhRTFNjaGVtYVR5cGUubmFtZSB8fFxuICAgICAgICAgICAgY3VzdG9tR3JhcGhRTFNjaGVtYVR5cGUubmFtZS5zdGFydHNXaXRoKCdfXycpXG4gICAgICAgICAgKSB7XG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuICAgICAgICAgIGNvbnN0IGF1dG9HcmFwaFFMU2NoZW1hVHlwZSA9IHRoaXMuZ3JhcGhRTEF1dG9TY2hlbWEuZ2V0VHlwZShcbiAgICAgICAgICAgIGN1c3RvbUdyYXBoUUxTY2hlbWFUeXBlLm5hbWVcbiAgICAgICAgICApO1xuXG4gICAgICAgICAgaWYgKGF1dG9HcmFwaFFMU2NoZW1hVHlwZSAmJiB0eXBlb2YgY3VzdG9tR3JhcGhRTFNjaGVtYVR5cGUuZ2V0RmllbGRzID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICBPYmplY3QudmFsdWVzKGN1c3RvbUdyYXBoUUxTY2hlbWFUeXBlLmdldEZpZWxkcygpKS5mb3JFYWNoKGZpZWxkID0+IHtcbiAgICAgICAgICAgICAgZmluZEFuZFJlcGxhY2VMYXN0VHlwZShmaWVsZCwgJ3R5cGUnKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgYXV0b0dyYXBoUUxTY2hlbWFUeXBlLl9maWVsZHMgPSB7XG4gICAgICAgICAgICAgIC4uLmF1dG9HcmFwaFFMU2NoZW1hVHlwZS5nZXRGaWVsZHMoKSxcbiAgICAgICAgICAgICAgLi4uY3VzdG9tR3JhcGhRTFNjaGVtYVR5cGUuZ2V0RmllbGRzKCksXG4gICAgICAgICAgICB9O1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICAgIHRoaXMuZ3JhcGhRTFNjaGVtYSA9IHN0aXRjaFNjaGVtYXMoe1xuICAgICAgICAgIHNjaGVtYXM6IFt0aGlzLmdyYXBoUUxTY2hlbWFEaXJlY3RpdmVzRGVmaW5pdGlvbnMsIHRoaXMuZ3JhcGhRTEF1dG9TY2hlbWFdLFxuICAgICAgICAgIG1lcmdlRGlyZWN0aXZlczogdHJ1ZSxcbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2UgaWYgKHR5cGVvZiB0aGlzLmdyYXBoUUxDdXN0b21UeXBlRGVmcyA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICB0aGlzLmdyYXBoUUxTY2hlbWEgPSBhd2FpdCB0aGlzLmdyYXBoUUxDdXN0b21UeXBlRGVmcyh7XG4gICAgICAgICAgZGlyZWN0aXZlc0RlZmluaXRpb25zU2NoZW1hOiB0aGlzLmdyYXBoUUxTY2hlbWFEaXJlY3RpdmVzRGVmaW5pdGlvbnMsXG4gICAgICAgICAgYXV0b1NjaGVtYTogdGhpcy5ncmFwaFFMQXV0b1NjaGVtYSxcbiAgICAgICAgICBzdGl0Y2hTY2hlbWFzLFxuICAgICAgICB9KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuZ3JhcGhRTFNjaGVtYSA9IHN0aXRjaFNjaGVtYXMoe1xuICAgICAgICAgIHNjaGVtYXM6IFtcbiAgICAgICAgICAgIHRoaXMuZ3JhcGhRTFNjaGVtYURpcmVjdGl2ZXNEZWZpbml0aW9ucyxcbiAgICAgICAgICAgIHRoaXMuZ3JhcGhRTEF1dG9TY2hlbWEsXG4gICAgICAgICAgICB0aGlzLmdyYXBoUUxDdXN0b21UeXBlRGVmcyxcbiAgICAgICAgICBdLFxuICAgICAgICAgIG1lcmdlRGlyZWN0aXZlczogdHJ1ZSxcbiAgICAgICAgfSk7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IGdyYXBoUUxTY2hlbWFUeXBlTWFwID0gdGhpcy5ncmFwaFFMU2NoZW1hLmdldFR5cGVNYXAoKTtcbiAgICAgIE9iamVjdC5rZXlzKGdyYXBoUUxTY2hlbWFUeXBlTWFwKS5mb3JFYWNoKGdyYXBoUUxTY2hlbWFUeXBlTmFtZSA9PiB7XG4gICAgICAgIGNvbnN0IGdyYXBoUUxTY2hlbWFUeXBlID0gZ3JhcGhRTFNjaGVtYVR5cGVNYXBbZ3JhcGhRTFNjaGVtYVR5cGVOYW1lXTtcbiAgICAgICAgaWYgKFxuICAgICAgICAgIHR5cGVvZiBncmFwaFFMU2NoZW1hVHlwZS5nZXRGaWVsZHMgPT09ICdmdW5jdGlvbicgJiZcbiAgICAgICAgICB0aGlzLmdyYXBoUUxDdXN0b21UeXBlRGVmcy5kZWZpbml0aW9uc1xuICAgICAgICApIHtcbiAgICAgICAgICBjb25zdCBncmFwaFFMQ3VzdG9tVHlwZURlZiA9IHRoaXMuZ3JhcGhRTEN1c3RvbVR5cGVEZWZzLmRlZmluaXRpb25zLmZpbmQoXG4gICAgICAgICAgICBkZWZpbml0aW9uID0+IGRlZmluaXRpb24ubmFtZS52YWx1ZSA9PT0gZ3JhcGhRTFNjaGVtYVR5cGVOYW1lXG4gICAgICAgICAgKTtcbiAgICAgICAgICBpZiAoZ3JhcGhRTEN1c3RvbVR5cGVEZWYpIHtcbiAgICAgICAgICAgIGNvbnN0IGdyYXBoUUxTY2hlbWFUeXBlRmllbGRNYXAgPSBncmFwaFFMU2NoZW1hVHlwZS5nZXRGaWVsZHMoKTtcbiAgICAgICAgICAgIE9iamVjdC5rZXlzKGdyYXBoUUxTY2hlbWFUeXBlRmllbGRNYXApLmZvckVhY2goZ3JhcGhRTFNjaGVtYVR5cGVGaWVsZE5hbWUgPT4ge1xuICAgICAgICAgICAgICBjb25zdCBncmFwaFFMU2NoZW1hVHlwZUZpZWxkID0gZ3JhcGhRTFNjaGVtYVR5cGVGaWVsZE1hcFtncmFwaFFMU2NoZW1hVHlwZUZpZWxkTmFtZV07XG4gICAgICAgICAgICAgIGlmICghZ3JhcGhRTFNjaGVtYVR5cGVGaWVsZC5hc3ROb2RlKSB7XG4gICAgICAgICAgICAgICAgY29uc3QgYXN0Tm9kZSA9IGdyYXBoUUxDdXN0b21UeXBlRGVmLmZpZWxkcy5maW5kKFxuICAgICAgICAgICAgICAgICAgZmllbGQgPT4gZmllbGQubmFtZS52YWx1ZSA9PT0gZ3JhcGhRTFNjaGVtYVR5cGVGaWVsZE5hbWVcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIGlmIChhc3ROb2RlKSB7XG4gICAgICAgICAgICAgICAgICBncmFwaFFMU2NoZW1hVHlwZUZpZWxkLmFzdE5vZGUgPSBhc3ROb2RlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9KTtcblxuICAgICAgU2NoZW1hRGlyZWN0aXZlVmlzaXRvci52aXNpdFNjaGVtYURpcmVjdGl2ZXMoXG4gICAgICAgIHRoaXMuZ3JhcGhRTFNjaGVtYSxcbiAgICAgICAgdGhpcy5ncmFwaFFMU2NoZW1hRGlyZWN0aXZlc1xuICAgICAgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5ncmFwaFFMU2NoZW1hID0gdGhpcy5ncmFwaFFMQXV0b1NjaGVtYTtcbiAgICB9XG5cbiAgICByZXR1cm4gdGhpcy5ncmFwaFFMU2NoZW1hO1xuICB9XG5cbiAgYWRkR3JhcGhRTFR5cGUodHlwZSwgdGhyb3dFcnJvciA9IGZhbHNlLCBpZ25vcmVSZXNlcnZlZCA9IGZhbHNlLCBpZ25vcmVDb25uZWN0aW9uID0gZmFsc2UpIHtcbiAgICBpZiAoXG4gICAgICAoIWlnbm9yZVJlc2VydmVkICYmIFJFU0VSVkVEX0dSQVBIUUxfVFlQRV9OQU1FUy5pbmNsdWRlcyh0eXBlLm5hbWUpKSB8fFxuICAgICAgdGhpcy5ncmFwaFFMVHlwZXMuZmluZChleGlzdGluZ1R5cGUgPT4gZXhpc3RpbmdUeXBlLm5hbWUgPT09IHR5cGUubmFtZSkgfHxcbiAgICAgICghaWdub3JlQ29ubmVjdGlvbiAmJiB0eXBlLm5hbWUuZW5kc1dpdGgoJ0Nvbm5lY3Rpb24nKSlcbiAgICApIHtcbiAgICAgIGNvbnN0IG1lc3NhZ2UgPSBgVHlwZSAke3R5cGUubmFtZX0gY291bGQgbm90IGJlIGFkZGVkIHRvIHRoZSBhdXRvIHNjaGVtYSBiZWNhdXNlIGl0IGNvbGxpZGVkIHdpdGggYW4gZXhpc3RpbmcgdHlwZS5gO1xuICAgICAgaWYgKHRocm93RXJyb3IpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKG1lc3NhZ2UpO1xuICAgICAgfVxuICAgICAgdGhpcy5sb2cud2FybihtZXNzYWdlKTtcbiAgICAgIHJldHVybiB1bmRlZmluZWQ7XG4gICAgfVxuICAgIHRoaXMuZ3JhcGhRTFR5cGVzLnB1c2godHlwZSk7XG4gICAgcmV0dXJuIHR5cGU7XG4gIH1cblxuICBhZGRHcmFwaFFMUXVlcnkoZmllbGROYW1lLCBmaWVsZCwgdGhyb3dFcnJvciA9IGZhbHNlLCBpZ25vcmVSZXNlcnZlZCA9IGZhbHNlKSB7XG4gICAgaWYgKFxuICAgICAgKCFpZ25vcmVSZXNlcnZlZCAmJiBSRVNFUlZFRF9HUkFQSFFMX1FVRVJZX05BTUVTLmluY2x1ZGVzKGZpZWxkTmFtZSkpIHx8XG4gICAgICB0aGlzLmdyYXBoUUxRdWVyaWVzW2ZpZWxkTmFtZV1cbiAgICApIHtcbiAgICAgIGNvbnN0IG1lc3NhZ2UgPSBgUXVlcnkgJHtmaWVsZE5hbWV9IGNvdWxkIG5vdCBiZSBhZGRlZCB0byB0aGUgYXV0byBzY2hlbWEgYmVjYXVzZSBpdCBjb2xsaWRlZCB3aXRoIGFuIGV4aXN0aW5nIGZpZWxkLmA7XG4gICAgICBpZiAodGhyb3dFcnJvcikge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IobWVzc2FnZSk7XG4gICAgICB9XG4gICAgICB0aGlzLmxvZy53YXJuKG1lc3NhZ2UpO1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG4gICAgdGhpcy5ncmFwaFFMUXVlcmllc1tmaWVsZE5hbWVdID0gZmllbGQ7XG4gICAgcmV0dXJuIGZpZWxkO1xuICB9XG5cbiAgYWRkR3JhcGhRTE11dGF0aW9uKGZpZWxkTmFtZSwgZmllbGQsIHRocm93RXJyb3IgPSBmYWxzZSwgaWdub3JlUmVzZXJ2ZWQgPSBmYWxzZSkge1xuICAgIGlmIChcbiAgICAgICghaWdub3JlUmVzZXJ2ZWQgJiYgUkVTRVJWRURfR1JBUEhRTF9NVVRBVElPTl9OQU1FUy5pbmNsdWRlcyhmaWVsZE5hbWUpKSB8fFxuICAgICAgdGhpcy5ncmFwaFFMTXV0YXRpb25zW2ZpZWxkTmFtZV1cbiAgICApIHtcbiAgICAgIGNvbnN0IG1lc3NhZ2UgPSBgTXV0YXRpb24gJHtmaWVsZE5hbWV9IGNvdWxkIG5vdCBiZSBhZGRlZCB0byB0aGUgYXV0byBzY2hlbWEgYmVjYXVzZSBpdCBjb2xsaWRlZCB3aXRoIGFuIGV4aXN0aW5nIGZpZWxkLmA7XG4gICAgICBpZiAodGhyb3dFcnJvcikge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IobWVzc2FnZSk7XG4gICAgICB9XG4gICAgICB0aGlzLmxvZy53YXJuKG1lc3NhZ2UpO1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG4gICAgdGhpcy5ncmFwaFFMTXV0YXRpb25zW2ZpZWxkTmFtZV0gPSBmaWVsZDtcbiAgICByZXR1cm4gZmllbGQ7XG4gIH1cblxuICBoYW5kbGVFcnJvcihlcnJvcikge1xuICAgIGlmIChlcnJvciBpbnN0YW5jZW9mIFBhcnNlLkVycm9yKSB7XG4gICAgICB0aGlzLmxvZy5lcnJvcignUGFyc2UgZXJyb3I6ICcsIGVycm9yKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5sb2cuZXJyb3IoJ1VuY2F1Z2h0IGludGVybmFsIHNlcnZlciBlcnJvci4nLCBlcnJvciwgZXJyb3Iuc3RhY2spO1xuICAgIH1cbiAgICB0aHJvdyB0b0dyYXBoUUxFcnJvcihlcnJvcik7XG4gIH1cblxuICBhc3luYyBfaW5pdGlhbGl6ZVNjaGVtYUFuZENvbmZpZygpIHtcbiAgICBjb25zdCBbc2NoZW1hQ29udHJvbGxlciwgcGFyc2VHcmFwaFFMQ29uZmlnXSA9IGF3YWl0IFByb21pc2UuYWxsKFtcbiAgICAgIHRoaXMuZGF0YWJhc2VDb250cm9sbGVyLmxvYWRTY2hlbWEoKSxcbiAgICAgIHRoaXMucGFyc2VHcmFwaFFMQ29udHJvbGxlci5nZXRHcmFwaFFMQ29uZmlnKCksXG4gICAgXSk7XG5cbiAgICB0aGlzLnNjaGVtYUNvbnRyb2xsZXIgPSBzY2hlbWFDb250cm9sbGVyO1xuXG4gICAgcmV0dXJuIHtcbiAgICAgIHBhcnNlR3JhcGhRTENvbmZpZyxcbiAgICB9O1xuICB9XG5cbiAgLyoqXG4gICAqIEdldHMgYWxsIGNsYXNzZXMgZm91bmQgYnkgdGhlIGBzY2hlbWFDb250cm9sbGVyYFxuICAgKiBtaW51cyB0aG9zZSBmaWx0ZXJlZCBvdXQgYnkgdGhlIGFwcCdzIHBhcnNlR3JhcGhRTENvbmZpZy5cbiAgICovXG4gIGFzeW5jIF9nZXRDbGFzc2VzRm9yU2NoZW1hKHBhcnNlR3JhcGhRTENvbmZpZzogUGFyc2VHcmFwaFFMQ29uZmlnKSB7XG4gICAgY29uc3QgeyBlbmFibGVkRm9yQ2xhc3NlcywgZGlzYWJsZWRGb3JDbGFzc2VzIH0gPSBwYXJzZUdyYXBoUUxDb25maWc7XG4gICAgY29uc3QgYWxsQ2xhc3NlcyA9IGF3YWl0IHRoaXMuc2NoZW1hQ29udHJvbGxlci5nZXRBbGxDbGFzc2VzKCk7XG5cbiAgICBpZiAoQXJyYXkuaXNBcnJheShlbmFibGVkRm9yQ2xhc3NlcykgfHwgQXJyYXkuaXNBcnJheShkaXNhYmxlZEZvckNsYXNzZXMpKSB7XG4gICAgICBsZXQgaW5jbHVkZWRDbGFzc2VzID0gYWxsQ2xhc3NlcztcbiAgICAgIGlmIChlbmFibGVkRm9yQ2xhc3Nlcykge1xuICAgICAgICBpbmNsdWRlZENsYXNzZXMgPSBhbGxDbGFzc2VzLmZpbHRlcihjbGF6eiA9PiB7XG4gICAgICAgICAgcmV0dXJuIGVuYWJsZWRGb3JDbGFzc2VzLmluY2x1ZGVzKGNsYXp6LmNsYXNzTmFtZSk7XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgaWYgKGRpc2FibGVkRm9yQ2xhc3Nlcykge1xuICAgICAgICAvLyBDbGFzc2VzIGluY2x1ZGVkIGluIGBlbmFibGVkRm9yQ2xhc3Nlc2AgdGhhdFxuICAgICAgICAvLyBhcmUgYWxzbyBwcmVzZW50IGluIGBkaXNhYmxlZEZvckNsYXNzZXNgIHdpbGxcbiAgICAgICAgLy8gc3RpbGwgYmUgZmlsdGVyZWQgb3V0XG4gICAgICAgIGluY2x1ZGVkQ2xhc3NlcyA9IGluY2x1ZGVkQ2xhc3Nlcy5maWx0ZXIoY2xhenogPT4ge1xuICAgICAgICAgIHJldHVybiAhZGlzYWJsZWRGb3JDbGFzc2VzLmluY2x1ZGVzKGNsYXp6LmNsYXNzTmFtZSk7XG4gICAgICAgIH0pO1xuICAgICAgfVxuXG4gICAgICB0aGlzLmlzVXNlcnNDbGFzc0Rpc2FibGVkID0gIWluY2x1ZGVkQ2xhc3Nlcy5zb21lKGNsYXp6ID0+IHtcbiAgICAgICAgcmV0dXJuIGNsYXp6LmNsYXNzTmFtZSA9PT0gJ19Vc2VyJztcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gaW5jbHVkZWRDbGFzc2VzO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gYWxsQ2xhc3NlcztcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBtZXRob2QgcmV0dXJucyBhIGxpc3Qgb2YgdHVwbGVzXG4gICAqIHRoYXQgcHJvdmlkZSB0aGUgcGFyc2VDbGFzcyBhbG9uZyB3aXRoXG4gICAqIGl0cyBwYXJzZUNsYXNzQ29uZmlnIHdoZXJlIHByb3ZpZGVkLlxuICAgKi9cbiAgX2dldFBhcnNlQ2xhc3Nlc1dpdGhDb25maWcocGFyc2VDbGFzc2VzLCBwYXJzZUdyYXBoUUxDb25maWc6IFBhcnNlR3JhcGhRTENvbmZpZykge1xuICAgIGNvbnN0IHsgY2xhc3NDb25maWdzIH0gPSBwYXJzZUdyYXBoUUxDb25maWc7XG5cbiAgICAvLyBNYWtlIHN1cmVzIHRoYXQgdGhlIGRlZmF1bHQgY2xhc3NlcyBhbmQgY2xhc3NlcyB0aGF0XG4gICAgLy8gc3RhcnRzIHdpdGggY2FwaXRhbGl6ZWQgbGV0dGVyIHdpbGwgYmUgZ2VuZXJhdGVkIGZpcnN0LlxuICAgIGNvbnN0IHNvcnRDbGFzc2VzID0gKGEsIGIpID0+IHtcbiAgICAgIGEgPSBhLmNsYXNzTmFtZTtcbiAgICAgIGIgPSBiLmNsYXNzTmFtZTtcbiAgICAgIGlmIChhWzBdID09PSAnXycpIHtcbiAgICAgICAgaWYgKGJbMF0gIT09ICdfJykge1xuICAgICAgICAgIHJldHVybiAtMTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgaWYgKGJbMF0gPT09ICdfJykge1xuICAgICAgICBpZiAoYVswXSAhPT0gJ18nKSB7XG4gICAgICAgICAgcmV0dXJuIDE7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGlmIChhID09PSBiKSB7XG4gICAgICAgIHJldHVybiAwO1xuICAgICAgfSBlbHNlIGlmIChhIDwgYikge1xuICAgICAgICByZXR1cm4gLTE7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gMTtcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgcmV0dXJuIHBhcnNlQ2xhc3Nlcy5zb3J0KHNvcnRDbGFzc2VzKS5tYXAocGFyc2VDbGFzcyA9PiB7XG4gICAgICBsZXQgcGFyc2VDbGFzc0NvbmZpZztcbiAgICAgIGlmIChjbGFzc0NvbmZpZ3MpIHtcbiAgICAgICAgcGFyc2VDbGFzc0NvbmZpZyA9IGNsYXNzQ29uZmlncy5maW5kKGMgPT4gYy5jbGFzc05hbWUgPT09IHBhcnNlQ2xhc3MuY2xhc3NOYW1lKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBbcGFyc2VDbGFzcywgcGFyc2VDbGFzc0NvbmZpZ107XG4gICAgfSk7XG4gIH1cblxuICBhc3luYyBfZ2V0RnVuY3Rpb25OYW1lcygpIHtcbiAgICByZXR1cm4gYXdhaXQgZ2V0RnVuY3Rpb25OYW1lcyh0aGlzLmFwcElkKS5maWx0ZXIoZnVuY3Rpb25OYW1lID0+IHtcbiAgICAgIGlmICgvXltfYS16QS1aXVtfYS16QS1aMC05XSokLy50ZXN0KGZ1bmN0aW9uTmFtZSkpIHtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLmxvZy53YXJuKFxuICAgICAgICAgIGBGdW5jdGlvbiAke2Z1bmN0aW9uTmFtZX0gY291bGQgbm90IGJlIGFkZGVkIHRvIHRoZSBhdXRvIHNjaGVtYSBiZWNhdXNlIEdyYXBoUUwgbmFtZXMgbXVzdCBtYXRjaCAvXltfYS16QS1aXVtfYS16QS1aMC05XSokLy5gXG4gICAgICAgICk7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDaGVja3MgZm9yIGNoYW5nZXMgdG8gdGhlIHBhcnNlQ2xhc3Nlc1xuICAgKiBvYmplY3RzIChpLmUuIGRhdGFiYXNlIHNjaGVtYSkgb3IgdG9cbiAgICogdGhlIHBhcnNlR3JhcGhRTENvbmZpZyBvYmplY3QuIElmIG5vXG4gICAqIGNoYW5nZXMgYXJlIGZvdW5kLCByZXR1cm4gdHJ1ZTtcbiAgICovXG4gIF9oYXNTY2hlbWFJbnB1dENoYW5nZWQocGFyYW1zOiB7XG4gICAgcGFyc2VDbGFzc2VzOiBhbnksXG4gICAgcGFyc2VDbGFzc2VzU3RyaW5nOiBzdHJpbmcsXG4gICAgcGFyc2VHcmFwaFFMQ29uZmlnOiA/UGFyc2VHcmFwaFFMQ29uZmlnLFxuICAgIGZ1bmN0aW9uTmFtZXNTdHJpbmc6IHN0cmluZyxcbiAgfSk6IGJvb2xlYW4ge1xuICAgIGNvbnN0IHsgcGFyc2VDbGFzc2VzLCBwYXJzZUNsYXNzZXNTdHJpbmcsIHBhcnNlR3JhcGhRTENvbmZpZywgZnVuY3Rpb25OYW1lc1N0cmluZyB9ID0gcGFyYW1zO1xuXG4gICAgaWYgKFxuICAgICAgSlNPTi5zdHJpbmdpZnkodGhpcy5wYXJzZUdyYXBoUUxDb25maWcpID09PSBKU09OLnN0cmluZ2lmeShwYXJzZUdyYXBoUUxDb25maWcpICYmXG4gICAgICB0aGlzLmZ1bmN0aW9uTmFtZXNTdHJpbmcgPT09IGZ1bmN0aW9uTmFtZXNTdHJpbmdcbiAgICApIHtcbiAgICAgIGlmICh0aGlzLnBhcnNlQ2xhc3NlcyA9PT0gcGFyc2VDbGFzc2VzKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH1cblxuICAgICAgaWYgKHRoaXMucGFyc2VDbGFzc2VzU3RyaW5nID09PSBwYXJzZUNsYXNzZXNTdHJpbmcpIHtcbiAgICAgICAgdGhpcy5wYXJzZUNsYXNzZXMgPSBwYXJzZUNsYXNzZXM7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gdHJ1ZTtcbiAgfVxufVxuXG5leHBvcnQgeyBQYXJzZUdyYXBoUUxTY2hlbWEgfTtcbiJdfQ==