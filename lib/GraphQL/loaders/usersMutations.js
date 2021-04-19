"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.load = void 0;

var _graphql = require("graphql");

var _graphqlRelay = require("graphql-relay");

var _UsersRouter = _interopRequireDefault(require("../../Routers/UsersRouter"));

var objectsMutations = _interopRequireWildcard(require("../helpers/objectsMutations"));

var _defaultGraphQLTypes = require("./defaultGraphQLTypes");

var _usersQueries = require("./usersQueries");

var _mutation = require("../transformers/mutation");

var _node = _interopRequireDefault(require("parse/node"));

function _getRequireWildcardCache() { if (typeof WeakMap !== "function") return null; var cache = new WeakMap(); _getRequireWildcardCache = function () { return cache; }; return cache; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

const usersRouter = new _UsersRouter.default();

const load = parseGraphQLSchema => {
  if (parseGraphQLSchema.isUsersClassDisabled) {
    return;
  }

  const signUpMutation = (0, _graphqlRelay.mutationWithClientMutationId)({
    name: 'SignUp',
    description: 'The signUp mutation can be used to create and sign up a new user.',
    inputFields: {
      fields: {
        descriptions: 'These are the fields of the new user to be created and signed up.',
        type: parseGraphQLSchema.parseClassTypes['_User'].classGraphQLCreateType
      }
    },
    outputFields: {
      viewer: {
        description: 'This is the new user that was created, signed up and returned as a viewer.',
        type: new _graphql.GraphQLNonNull(parseGraphQLSchema.viewerType)
      }
    },
    mutateAndGetPayload: async (args, context, mutationInfo) => {
      try {
        const {
          fields
        } = args;
        const {
          config,
          auth,
          info
        } = context;
        const parseFields = await (0, _mutation.transformTypes)('create', fields, {
          className: '_User',
          parseGraphQLSchema,
          req: {
            config,
            auth,
            info
          }
        });
        const {
          sessionToken,
          objectId
        } = await objectsMutations.createObject('_User', parseFields, config, auth, info);
        context.info.sessionToken = sessionToken;
        return {
          viewer: await (0, _usersQueries.getUserFromSessionToken)(context, mutationInfo, 'viewer.user.', objectId)
        };
      } catch (e) {
        parseGraphQLSchema.handleError(e);
      }
    }
  });
  parseGraphQLSchema.addGraphQLType(signUpMutation.args.input.type.ofType, true, true);
  parseGraphQLSchema.addGraphQLType(signUpMutation.type, true, true);
  parseGraphQLSchema.addGraphQLMutation('signUp', signUpMutation, true, true);
  const logInWithMutation = (0, _graphqlRelay.mutationWithClientMutationId)({
    name: 'LogInWith',
    description: 'The logInWith mutation can be used to signup, login user with 3rd party authentication system. This mutation create a user if the authData do not correspond to an existing one.',
    inputFields: {
      authData: {
        descriptions: 'This is the auth data of your custom auth provider',
        type: new _graphql.GraphQLNonNull(_defaultGraphQLTypes.OBJECT)
      },
      fields: {
        descriptions: 'These are the fields of the user to be created/updated and logged in.',
        type: new _graphql.GraphQLInputObjectType({
          name: 'UserLoginWithInput',
          fields: () => {
            const classGraphQLCreateFields = parseGraphQLSchema.parseClassTypes['_User'].classGraphQLCreateType.getFields();
            return Object.keys(classGraphQLCreateFields).reduce((fields, fieldName) => {
              if (fieldName !== 'password' && fieldName !== 'username' && fieldName !== 'authData') {
                fields[fieldName] = classGraphQLCreateFields[fieldName];
              }

              return fields;
            }, {});
          }
        })
      }
    },
    outputFields: {
      viewer: {
        description: 'This is the new user that was created, signed up and returned as a viewer.',
        type: new _graphql.GraphQLNonNull(parseGraphQLSchema.viewerType)
      }
    },
    mutateAndGetPayload: async (args, context, mutationInfo) => {
      try {
        const {
          fields,
          authData
        } = args;
        const {
          config,
          auth,
          info
        } = context;
        const parseFields = await (0, _mutation.transformTypes)('create', fields, {
          className: '_User',
          parseGraphQLSchema,
          req: {
            config,
            auth,
            info
          }
        });
        const {
          sessionToken,
          objectId
        } = await objectsMutations.createObject('_User', _objectSpread(_objectSpread({}, parseFields), {}, {
          authData
        }), config, auth, info);
        context.info.sessionToken = sessionToken;
        return {
          viewer: await (0, _usersQueries.getUserFromSessionToken)(context, mutationInfo, 'viewer.user.', objectId)
        };
      } catch (e) {
        parseGraphQLSchema.handleError(e);
      }
    }
  });
  parseGraphQLSchema.addGraphQLType(logInWithMutation.args.input.type.ofType, true, true);
  parseGraphQLSchema.addGraphQLType(logInWithMutation.type, true, true);
  parseGraphQLSchema.addGraphQLMutation('logInWith', logInWithMutation, true, true);
  const logInMutation = (0, _graphqlRelay.mutationWithClientMutationId)({
    name: 'LogIn',
    description: 'The logIn mutation can be used to log in an existing user.',
    inputFields: {
      username: {
        description: 'This is the username used to log in the user.',
        type: new _graphql.GraphQLNonNull(_graphql.GraphQLString)
      },
      password: {
        description: 'This is the password used to log in the user.',
        type: new _graphql.GraphQLNonNull(_graphql.GraphQLString)
      }
    },
    outputFields: {
      viewer: {
        description: 'This is the existing user that was logged in and returned as a viewer.',
        type: new _graphql.GraphQLNonNull(parseGraphQLSchema.viewerType)
      }
    },
    mutateAndGetPayload: async (args, context, mutationInfo) => {
      try {
        const {
          username,
          password
        } = args;
        const {
          config,
          auth,
          info
        } = context;
        const {
          sessionToken,
          objectId
        } = (await usersRouter.handleLogIn({
          body: {
            username,
            password
          },
          query: {},
          config,
          auth,
          info
        })).response;
        context.info.sessionToken = sessionToken;
        return {
          viewer: await (0, _usersQueries.getUserFromSessionToken)(context, mutationInfo, 'viewer.user.', objectId)
        };
      } catch (e) {
        parseGraphQLSchema.handleError(e);
      }
    }
  });
  parseGraphQLSchema.addGraphQLType(logInMutation.args.input.type.ofType, true, true);
  parseGraphQLSchema.addGraphQLType(logInMutation.type, true, true);
  parseGraphQLSchema.addGraphQLMutation('logIn', logInMutation, true, true);
  const logOutMutation = (0, _graphqlRelay.mutationWithClientMutationId)({
    name: 'LogOut',
    description: 'The logOut mutation can be used to log out an existing user.',
    outputFields: {
      ok: {
        description: "It's always true.",
        type: new _graphql.GraphQLNonNull(_graphql.GraphQLBoolean)
      }
    },
    mutateAndGetPayload: async (_args, context) => {
      try {
        const {
          config,
          auth,
          info
        } = context;
        await usersRouter.handleLogOut({
          config,
          auth,
          info
        });
        return {
          ok: true
        };
      } catch (e) {
        parseGraphQLSchema.handleError(e);
      }
    }
  });
  parseGraphQLSchema.addGraphQLType(logOutMutation.args.input.type.ofType, true, true);
  parseGraphQLSchema.addGraphQLType(logOutMutation.type, true, true);
  parseGraphQLSchema.addGraphQLMutation('logOut', logOutMutation, true, true);
  const resetPasswordMutation = (0, _graphqlRelay.mutationWithClientMutationId)({
    name: 'ResetPassword',
    description: 'The resetPassword mutation can be used to reset the password of an existing user.',
    inputFields: {
      email: {
        descriptions: 'Email of the user that should receive the reset email',
        type: new _graphql.GraphQLNonNull(_graphql.GraphQLString)
      }
    },
    outputFields: {
      ok: {
        description: "It's always true.",
        type: new _graphql.GraphQLNonNull(_graphql.GraphQLBoolean)
      }
    },
    mutateAndGetPayload: async ({
      email
    }, context) => {
      const {
        config,
        auth,
        info
      } = context;
      await usersRouter.handleResetRequest({
        body: {
          email
        },
        config,
        auth,
        info
      });
      return {
        ok: true
      };
    }
  });
  parseGraphQLSchema.addGraphQLType(resetPasswordMutation.args.input.type.ofType, true, true);
  parseGraphQLSchema.addGraphQLType(resetPasswordMutation.type, true, true);
  parseGraphQLSchema.addGraphQLMutation('resetPassword', resetPasswordMutation, true, true);
  const confirmResetPasswordMutation = (0, _graphqlRelay.mutationWithClientMutationId)({
    name: 'ConfirmResetPassword',
    description: 'The confirmResetPassword mutation can be used to reset the password of an existing user.',
    inputFields: {
      username: {
        descriptions: 'Username of the user that have received the reset email',
        type: new _graphql.GraphQLNonNull(_graphql.GraphQLString)
      },
      password: {
        descriptions: 'New password of the user',
        type: new _graphql.GraphQLNonNull(_graphql.GraphQLString)
      },
      token: {
        descriptions: 'Reset token that was emailed to the user',
        type: new _graphql.GraphQLNonNull(_graphql.GraphQLString)
      }
    },
    outputFields: {
      ok: {
        description: "It's always true.",
        type: new _graphql.GraphQLNonNull(_graphql.GraphQLBoolean)
      }
    },
    mutateAndGetPayload: async ({
      username,
      password,
      token
    }, context) => {
      const {
        config
      } = context;

      if (!username) {
        throw new _node.default.Error(_node.default.Error.USERNAME_MISSING, 'you must provide a username');
      }

      if (!password) {
        throw new _node.default.Error(_node.default.Error.PASSWORD_MISSING, 'you must provide a password');
      }

      if (!token) {
        throw new _node.default.Error(_node.default.Error.OTHER_CAUSE, 'you must provide a token');
      }

      const userController = config.userController;
      await userController.updatePassword(username, token, password);
      return {
        ok: true
      };
    }
  });
  parseGraphQLSchema.addGraphQLType(confirmResetPasswordMutation.args.input.type.ofType, true, true);
  parseGraphQLSchema.addGraphQLType(confirmResetPasswordMutation.type, true, true);
  parseGraphQLSchema.addGraphQLMutation('confirmResetPassword', confirmResetPasswordMutation, true, true);
  const sendVerificationEmailMutation = (0, _graphqlRelay.mutationWithClientMutationId)({
    name: 'SendVerificationEmail',
    description: 'The sendVerificationEmail mutation can be used to send the verification email again.',
    inputFields: {
      email: {
        descriptions: 'Email of the user that should receive the verification email',
        type: new _graphql.GraphQLNonNull(_graphql.GraphQLString)
      }
    },
    outputFields: {
      ok: {
        description: "It's always true.",
        type: new _graphql.GraphQLNonNull(_graphql.GraphQLBoolean)
      }
    },
    mutateAndGetPayload: async ({
      email
    }, context) => {
      try {
        const {
          config,
          auth,
          info
        } = context;
        await usersRouter.handleVerificationEmailRequest({
          body: {
            email
          },
          config,
          auth,
          info
        });
        return {
          ok: true
        };
      } catch (e) {
        parseGraphQLSchema.handleError(e);
      }
    }
  });
  parseGraphQLSchema.addGraphQLType(sendVerificationEmailMutation.args.input.type.ofType, true, true);
  parseGraphQLSchema.addGraphQLType(sendVerificationEmailMutation.type, true, true);
  parseGraphQLSchema.addGraphQLMutation('sendVerificationEmail', sendVerificationEmailMutation, true, true);
};

exports.load = load;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9HcmFwaFFML2xvYWRlcnMvdXNlcnNNdXRhdGlvbnMuanMiXSwibmFtZXMiOlsidXNlcnNSb3V0ZXIiLCJVc2Vyc1JvdXRlciIsImxvYWQiLCJwYXJzZUdyYXBoUUxTY2hlbWEiLCJpc1VzZXJzQ2xhc3NEaXNhYmxlZCIsInNpZ25VcE11dGF0aW9uIiwibmFtZSIsImRlc2NyaXB0aW9uIiwiaW5wdXRGaWVsZHMiLCJmaWVsZHMiLCJkZXNjcmlwdGlvbnMiLCJ0eXBlIiwicGFyc2VDbGFzc1R5cGVzIiwiY2xhc3NHcmFwaFFMQ3JlYXRlVHlwZSIsIm91dHB1dEZpZWxkcyIsInZpZXdlciIsIkdyYXBoUUxOb25OdWxsIiwidmlld2VyVHlwZSIsIm11dGF0ZUFuZEdldFBheWxvYWQiLCJhcmdzIiwiY29udGV4dCIsIm11dGF0aW9uSW5mbyIsImNvbmZpZyIsImF1dGgiLCJpbmZvIiwicGFyc2VGaWVsZHMiLCJjbGFzc05hbWUiLCJyZXEiLCJzZXNzaW9uVG9rZW4iLCJvYmplY3RJZCIsIm9iamVjdHNNdXRhdGlvbnMiLCJjcmVhdGVPYmplY3QiLCJlIiwiaGFuZGxlRXJyb3IiLCJhZGRHcmFwaFFMVHlwZSIsImlucHV0Iiwib2ZUeXBlIiwiYWRkR3JhcGhRTE11dGF0aW9uIiwibG9nSW5XaXRoTXV0YXRpb24iLCJhdXRoRGF0YSIsIk9CSkVDVCIsIkdyYXBoUUxJbnB1dE9iamVjdFR5cGUiLCJjbGFzc0dyYXBoUUxDcmVhdGVGaWVsZHMiLCJnZXRGaWVsZHMiLCJPYmplY3QiLCJrZXlzIiwicmVkdWNlIiwiZmllbGROYW1lIiwibG9nSW5NdXRhdGlvbiIsInVzZXJuYW1lIiwiR3JhcGhRTFN0cmluZyIsInBhc3N3b3JkIiwiaGFuZGxlTG9nSW4iLCJib2R5IiwicXVlcnkiLCJyZXNwb25zZSIsImxvZ091dE11dGF0aW9uIiwib2siLCJHcmFwaFFMQm9vbGVhbiIsIl9hcmdzIiwiaGFuZGxlTG9nT3V0IiwicmVzZXRQYXNzd29yZE11dGF0aW9uIiwiZW1haWwiLCJoYW5kbGVSZXNldFJlcXVlc3QiLCJjb25maXJtUmVzZXRQYXNzd29yZE11dGF0aW9uIiwidG9rZW4iLCJQYXJzZSIsIkVycm9yIiwiVVNFUk5BTUVfTUlTU0lORyIsIlBBU1NXT1JEX01JU1NJTkciLCJPVEhFUl9DQVVTRSIsInVzZXJDb250cm9sbGVyIiwidXBkYXRlUGFzc3dvcmQiLCJzZW5kVmVyaWZpY2F0aW9uRW1haWxNdXRhdGlvbiIsImhhbmRsZVZlcmlmaWNhdGlvbkVtYWlsUmVxdWVzdCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOzs7Ozs7Ozs7Ozs7OztBQUVBLE1BQU1BLFdBQVcsR0FBRyxJQUFJQyxvQkFBSixFQUFwQjs7QUFFQSxNQUFNQyxJQUFJLEdBQUdDLGtCQUFrQixJQUFJO0FBQ2pDLE1BQUlBLGtCQUFrQixDQUFDQyxvQkFBdkIsRUFBNkM7QUFDM0M7QUFDRDs7QUFFRCxRQUFNQyxjQUFjLEdBQUcsZ0RBQTZCO0FBQ2xEQyxJQUFBQSxJQUFJLEVBQUUsUUFENEM7QUFFbERDLElBQUFBLFdBQVcsRUFBRSxtRUFGcUM7QUFHbERDLElBQUFBLFdBQVcsRUFBRTtBQUNYQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkMsUUFBQUEsWUFBWSxFQUFFLG1FQURSO0FBRU5DLFFBQUFBLElBQUksRUFBRVIsa0JBQWtCLENBQUNTLGVBQW5CLENBQW1DLE9BQW5DLEVBQTRDQztBQUY1QztBQURHLEtBSHFDO0FBU2xEQyxJQUFBQSxZQUFZLEVBQUU7QUFDWkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05SLFFBQUFBLFdBQVcsRUFBRSw0RUFEUDtBQUVOSSxRQUFBQSxJQUFJLEVBQUUsSUFBSUssdUJBQUosQ0FBbUJiLGtCQUFrQixDQUFDYyxVQUF0QztBQUZBO0FBREksS0FUb0M7QUFlbERDLElBQUFBLG1CQUFtQixFQUFFLE9BQU9DLElBQVAsRUFBYUMsT0FBYixFQUFzQkMsWUFBdEIsS0FBdUM7QUFD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QW5DLENBQXlDeEIsSUFBekMsQ0FBOEN5QixNQURoRCxFQUVFLElBRkYsRUFHRSxJQUhGO0FBS0FqQyxFQUFBQSxrQkFBa0IsQ0FBQytCLGNBQW5CLENBQWtDdUMsNkJBQTZCLENBQUM5RCxJQUFoRSxFQUFzRSxJQUF0RSxFQUE0RSxJQUE1RTtBQUNBUixFQUFBQSxrQkFBa0IsQ0FBQ2tDLGtCQUFuQixDQUNFLHVCQURGLEVBRUVvQyw2QkFGRixFQUdFLElBSEYsRUFJRSxJQUpGO0FBTUQsQ0F6VkQiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBHcmFwaFFMTm9uTnVsbCwgR3JhcGhRTFN0cmluZywgR3JhcGhRTEJvb2xlYW4sIEdyYXBoUUxJbnB1dE9iamVjdFR5cGUgfSBmcm9tICdncmFwaHFsJztcbmltcG9ydCB7IG11dGF0aW9uV2l0aENsaWVudE11dGF0aW9uSWQgfSBmcm9tICdncmFwaHFsLXJlbGF5JztcbmltcG9ydCBVc2Vyc1JvdXRlciBmcm9tICcuLi8uLi9Sb3V0ZXJzL1VzZXJzUm91dGVyJztcbmltcG9ydCAqIGFzIG9iamVjdHNNdXRhdGlvbnMgZnJvbSAnLi4vaGVscGVycy9vYmplY3RzTXV0YXRpb25zJztcbmltcG9ydCB7IE9CSkVDVCB9IGZyb20gJy4vZGVmYXVsdEdyYXBoUUxUeXBlcyc7XG5pbXBvcnQgeyBnZXRVc2VyRnJvbVNlc3Npb25Ub2tlbiB9IGZyb20gJy4vdXNlcnNRdWVyaWVzJztcbmltcG9ydCB7IHRyYW5zZm9ybVR5cGVzIH0gZnJvbSAnLi4vdHJhbnNmb3JtZXJzL211dGF0aW9uJztcbmltcG9ydCBQYXJzZSBmcm9tICdwYXJzZS9ub2RlJztcblxuY29uc3QgdXNlcnNSb3V0ZXIgPSBuZXcgVXNlcnNSb3V0ZXIoKTtcblxuY29uc3QgbG9hZCA9IHBhcnNlR3JhcGhRTFNjaGVtYSA9PiB7XG4gIGlmIChwYXJzZUdyYXBoUUxTY2hlbWEuaXNVc2Vyc0NsYXNzRGlzYWJsZWQpIHtcbiAgICByZXR1cm47XG4gIH1cblxuICBjb25zdCBzaWduVXBNdXRhdGlvbiA9IG11dGF0aW9uV2l0aENsaWVudE11dGF0aW9uSWQoe1xuICAgIG5hbWU6ICdTaWduVXAnLFxuICAgIGRlc2NyaXB0aW9uOiAnVGhlIHNpZ25VcCBtdXRhdGlvbiBjYW4gYmUgdXNlZCB0byBjcmVhdGUgYW5kIHNpZ24gdXAgYSBuZXcgdXNlci4nLFxuICAgIGlucHV0RmllbGRzOiB7XG4gICAgICBmaWVsZHM6IHtcbiAgICAgICAgZGVzY3JpcHRpb25zOiAnVGhlc2UgYXJlIHRoZSBmaWVsZHMgb2YgdGhlIG5ldyB1c2VyIHRvIGJlIGNyZWF0ZWQgYW5kIHNpZ25lZCB1cC4nLFxuICAgICAgICB0eXBlOiBwYXJzZUdyYXBoUUxTY2hlbWEucGFyc2VDbGFzc1R5cGVzWydfVXNlciddLmNsYXNzR3JhcGhRTENyZWF0ZVR5cGUsXG4gICAgICB9LFxuICAgIH0sXG4gICAgb3V0cHV0RmllbGRzOiB7XG4gICAgICB2aWV3ZXI6IHtcbiAgICAgICAgZGVzY3JpcHRpb246ICdUaGlzIGlzIHRoZSBuZXcgdXNlciB0aGF0IHdhcyBjcmVhdGVkLCBzaWduZWQgdXAgYW5kIHJldHVybmVkIGFzIGEgdmlld2VyLicsXG4gICAgICAgIHR5cGU6IG5ldyBHcmFwaFFMTm9uTnVsbChwYXJzZUdyYXBoUUxTY2hlbWEudmlld2VyVHlwZSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgbXV0YXRlQW5kR2V0UGF5bG9hZDogYXN5bmMgKGFyZ3MsIGNvbnRleHQsIG11dGF0aW9uSW5mbykgPT4ge1xuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgeyBmaWVsZHMgfSA9IGFyZ3M7XG4gICAgICAgIGNvbnN0IHsgY29uZmlnLCBhdXRoLCBpbmZvIH0gPSBjb250ZXh0O1xuXG4gICAgICAgIGNvbnN0IHBhcnNlRmllbGRzID0gYXdhaXQgdHJhbnNmb3JtVHlwZXMoJ2NyZWF0ZScsIGZpZWxkcywge1xuICAgICAgICAgIGNsYXNzTmFtZTogJ19Vc2VyJyxcbiAgICAgICAgICBwYXJzZUdyYXBoUUxTY2hlbWEsXG4gICAgICAgICAgcmVxOiB7IGNvbmZpZywgYXV0aCwgaW5mbyB9LFxuICAgICAgICB9KTtcblxuICAgICAgICBjb25zdCB7IHNlc3Npb25Ub2tlbiwgb2JqZWN0SWQgfSA9IGF3YWl0IG9iamVjdHNNdXRhdGlvbnMuY3JlYXRlT2JqZWN0KFxuICAgICAgICAgICdfVXNlcicsXG4gICAgICAgICAgcGFyc2VGaWVsZHMsXG4gICAgICAgICAgY29uZmlnLFxuICAgICAgICAgIGF1dGgsXG4gICAgICAgICAgaW5mb1xuICAgICAgICApO1xuXG4gICAgICAgIGNvbnRleHQuaW5mby5zZXNzaW9uVG9rZW4gPSBzZXNzaW9uVG9rZW47XG5cbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICB2aWV3ZXI6IGF3YWl0IGdldFVzZXJGcm9tU2Vzc2lvblRva2VuKGNvbnRleHQsIG11dGF0aW9uSW5mbywgJ3ZpZXdlci51c2VyLicsIG9iamVjdElkKSxcbiAgICAgICAgfTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgcGFyc2VHcmFwaFFMU2NoZW1hLmhhbmRsZUVycm9yKGUpO1xuICAgICAgfVxuICAgIH0sXG4gIH0pO1xuXG4gIHBhcnNlR3JhcGhRTFNjaGVtYS5hZGRHcmFwaFFMVHlwZShzaWduVXBNdXRhdGlvbi5hcmdzLmlucHV0LnR5cGUub2ZUeXBlLCB0cnVlLCB0cnVlKTtcbiAgcGFyc2VHcmFwaFFMU2NoZW1hLmFkZEdyYXBoUUxUeXBlKHNpZ25VcE11dGF0aW9uLnR5cGUsIHRydWUsIHRydWUpO1xuICBwYXJzZUdyYXBoUUxTY2hlbWEuYWRkR3JhcGhRTE11dGF0aW9uKCdzaWduVXAnLCBzaWduVXBNdXRhdGlvbiwgdHJ1ZSwgdHJ1ZSk7XG4gIGNvbnN0IGxvZ0luV2l0aE11dGF0aW9uID0gbXV0YXRpb25XaXRoQ2xpZW50TXV0YXRpb25JZCh7XG4gICAgbmFtZTogJ0xvZ0luV2l0aCcsXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnVGhlIGxvZ0luV2l0aCBtdXRhdGlvbiBjYW4gYmUgdXNlZCB0byBzaWdudXAsIGxvZ2luIHVzZXIgd2l0aCAzcmQgcGFydHkgYXV0aGVudGljYXRpb24gc3lzdGVtLiBUaGlzIG11dGF0aW9uIGNyZWF0ZSBhIHVzZXIgaWYgdGhlIGF1dGhEYXRhIGRvIG5vdCBjb3JyZXNwb25kIHRvIGFuIGV4aXN0aW5nIG9uZS4nLFxuICAgIGlucHV0RmllbGRzOiB7XG4gICAgICBhdXRoRGF0YToge1xuICAgICAgICBkZXNjcmlwdGlvbnM6ICdUaGlzIGlzIHRoZSBhdXRoIGRhdGEgb2YgeW91ciBjdXN0b20gYXV0aCBwcm92aWRlcicsXG4gICAgICAgIHR5cGU6IG5ldyBHcmFwaFFMTm9uTnVsbChPQkpFQ1QpLFxuICAgICAgfSxcbiAgICAgIGZpZWxkczoge1xuICAgICAgICBkZXNjcmlwdGlvbnM6ICdUaGVzZSBhcmUgdGhlIGZpZWxkcyBvZiB0aGUgdXNlciB0byBiZSBjcmVhdGVkL3VwZGF0ZWQgYW5kIGxvZ2dlZCBpbi4nLFxuICAgICAgICB0eXBlOiBuZXcgR3JhcGhRTElucHV0T2JqZWN0VHlwZSh7XG4gICAgICAgICAgbmFtZTogJ1VzZXJMb2dpbldpdGhJbnB1dCcsXG4gICAgICAgICAgZmllbGRzOiAoKSA9PiB7XG4gICAgICAgICAgICBjb25zdCBjbGFzc0dyYXBoUUxDcmVhdGVGaWVsZHMgPSBwYXJzZUdyYXBoUUxTY2hlbWEucGFyc2VDbGFzc1R5cGVzW1xuICAgICAgICAgICAgICAnX1VzZXInXG4gICAgICAgICAgICBdLmNsYXNzR3JhcGhRTENyZWF0ZVR5cGUuZ2V0RmllbGRzKCk7XG4gICAgICAgICAgICByZXR1cm4gT2JqZWN0LmtleXMoY2xhc3NHcmFwaFFMQ3JlYXRlRmllbGRzKS5yZWR1Y2UoKGZpZWxkcywgZmllbGROYW1lKSA9PiB7XG4gICAgICAgICAgICAgIGlmIChcbiAgICAgICAgICAgICAgICBmaWVsZE5hbWUgIT09ICdwYXNzd29yZCcgJiZcbiAgICAgICAgICAgICAgICBmaWVsZE5hbWUgIT09ICd1c2VybmFtZScgJiZcbiAgICAgICAgICAgICAgICBmaWVsZE5hbWUgIT09ICdhdXRoRGF0YSdcbiAgICAgICAgICAgICAgKSB7XG4gICAgICAgICAgICAgICAgZmllbGRzW2ZpZWxkTmFtZV0gPSBjbGFzc0dyYXBoUUxDcmVhdGVGaWVsZHNbZmllbGROYW1lXTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICByZXR1cm4gZmllbGRzO1xuICAgICAgICAgICAgfSwge30pO1xuICAgICAgICAgIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIG91dHB1dEZpZWxkczoge1xuICAgICAgdmlld2VyOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiAnVGhpcyBpcyB0aGUgbmV3IHVzZXIgdGhhdCB3YXMgY3JlYXRlZCwgc2lnbmVkIHVwIGFuZCByZXR1cm5lZCBhcyBhIHZpZXdlci4nLFxuICAgICAgICB0eXBlOiBuZXcgR3JhcGhRTE5vbk51bGwocGFyc2VHcmFwaFFMU2NoZW1hLnZpZXdlclR5cGUpLFxuICAgICAgfSxcbiAgICB9LFxuICAgIG11dGF0ZUFuZEdldFBheWxvYWQ6IGFzeW5jIChhcmdzLCBjb250ZXh0LCBtdXRhdGlvbkluZm8pID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHsgZmllbGRzLCBhdXRoRGF0YSB9ID0gYXJncztcbiAgICAgICAgY29uc3QgeyBjb25maWcsIGF1dGgsIGluZm8gfSA9IGNvbnRleHQ7XG5cbiAgICAgICAgY29uc3QgcGFyc2VGaWVsZHMgPSBhd2FpdCB0cmFuc2Zvcm1UeXBlcygnY3JlYXRlJywgZmllbGRzLCB7XG4gICAgICAgICAgY2xhc3NOYW1lOiAnX1VzZXInLFxuICAgICAgICAgIHBhcnNlR3JhcGhRTFNjaGVtYSxcbiAgICAgICAgICByZXE6IHsgY29uZmlnLCBhdXRoLCBpbmZvIH0sXG4gICAgICAgIH0pO1xuXG4gICAgICAgIGNvbnN0IHsgc2Vzc2lvblRva2VuLCBvYmplY3RJZCB9ID0gYXdhaXQgb2JqZWN0c011dGF0aW9ucy5jcmVhdGVPYmplY3QoXG4gICAgICAgICAgJ19Vc2VyJyxcbiAgICAgICAgICB7IC4uLnBhcnNlRmllbGRzLCBhdXRoRGF0YSB9LFxuICAgICAgICAgIGNvbmZpZyxcbiAgICAgICAgICBhdXRoLFxuICAgICAgICAgIGluZm9cbiAgICAgICAgKTtcblxuICAgICAgICBjb250ZXh0LmluZm8uc2Vzc2lvblRva2VuID0gc2Vzc2lvblRva2VuO1xuXG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgdmlld2VyOiBhd2FpdCBnZXRVc2VyRnJvbVNlc3Npb25Ub2tlbihjb250ZXh0LCBtdXRhdGlvbkluZm8sICd2aWV3ZXIudXNlci4nLCBvYmplY3RJZCksXG4gICAgICAgIH07XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHBhcnNlR3JhcGhRTFNjaGVtYS5oYW5kbGVFcnJvcihlKTtcbiAgICAgIH1cbiAgICB9LFxuICB9KTtcblxuICBwYXJzZUdyYXBoUUxTY2hlbWEuYWRkR3JhcGhRTFR5cGUobG9nSW5XaXRoTXV0YXRpb24uYXJncy5pbnB1dC50eXBlLm9mVHlwZSwgdHJ1ZSwgdHJ1ZSk7XG4gIHBhcnNlR3JhcGhRTFNjaGVtYS5hZGRHcmFwaFFMVHlwZShsb2dJbldpdGhNdXRhdGlvbi50eXBlLCB0cnVlLCB0cnVlKTtcbiAgcGFyc2VHcmFwaFFMU2NoZW1hLmFkZEdyYXBoUUxNdXRhdGlvbignbG9nSW5XaXRoJywgbG9nSW5XaXRoTXV0YXRpb24sIHRydWUsIHRydWUpO1xuXG4gIGNvbnN0IGxvZ0luTXV0YXRpb24gPSBtdXRhdGlvbldpdGhDbGllbnRNdXRhdGlvbklkKHtcbiAgICBuYW1lOiAnTG9nSW4nLFxuICAgIGRlc2NyaXB0aW9uOiAnVGhlIGxvZ0luIG11dGF0aW9uIGNhbiBiZSB1c2VkIHRvIGxvZyBpbiBhbiBleGlzdGluZyB1c2VyLicsXG4gICAgaW5wdXRGaWVsZHM6IHtcbiAgICAgIHVzZXJuYW1lOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiAnVGhpcyBpcyB0aGUgdXNlcm5hbWUgdXNlZCB0byBsb2cgaW4gdGhlIHVzZXIuJyxcbiAgICAgICAgdHlwZTogbmV3IEdyYXBoUUxOb25OdWxsKEdyYXBoUUxTdHJpbmcpLFxuICAgICAgfSxcbiAgICAgIHBhc3N3b3JkOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiAnVGhpcyBpcyB0aGUgcGFzc3dvcmQgdXNlZCB0byBsb2cgaW4gdGhlIHVzZXIuJyxcbiAgICAgICAgdHlwZTogbmV3IEdyYXBoUUxOb25OdWxsKEdyYXBoUUxTdHJpbmcpLFxuICAgICAgfSxcbiAgICB9LFxuICAgIG91dHB1dEZpZWxkczoge1xuICAgICAgdmlld2VyOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiAnVGhpcyBpcyB0aGUgZXhpc3RpbmcgdXNlciB0aGF0IHdhcyBsb2dnZWQgaW4gYW5kIHJldHVybmVkIGFzIGEgdmlld2VyLicsXG4gICAgICAgIHR5cGU6IG5ldyBHcmFwaFFMTm9uTnVsbChwYXJzZUdyYXBoUUxTY2hlbWEudmlld2VyVHlwZSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgbXV0YXRlQW5kR2V0UGF5bG9hZDogYXN5bmMgKGFyZ3MsIGNvbnRleHQsIG11dGF0aW9uSW5mbykgPT4ge1xuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgeyB1c2VybmFtZSwgcGFzc3dvcmQgfSA9IGFyZ3M7XG4gICAgICAgIGNvbnN0IHsgY29uZmlnLCBhdXRoLCBpbmZvIH0gPSBjb250ZXh0O1xuXG4gICAgICAgIGNvbnN0IHsgc2Vzc2lvblRva2VuLCBvYmplY3RJZCB9ID0gKFxuICAgICAgICAgIGF3YWl0IHVzZXJzUm91dGVyLmhhbmRsZUxvZ0luKHtcbiAgICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgICAgdXNlcm5hbWUsXG4gICAgICAgICAgICAgIHBhc3N3b3JkLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHF1ZXJ5OiB7fSxcbiAgICAgICAgICAgIGNvbmZpZyxcbiAgICAgICAgICAgIGF1dGgsXG4gICAgICAgICAgICBpbmZvLFxuICAgICAgICAgIH0pXG4gICAgICAgICkucmVzcG9uc2U7XG5cbiAgICAgICAgY29udGV4dC5pbmZvLnNlc3Npb25Ub2tlbiA9IHNlc3Npb25Ub2tlbjtcblxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgIHZpZXdlcjogYXdhaXQgZ2V0VXNlckZyb21TZXNzaW9uVG9rZW4oY29udGV4dCwgbXV0YXRpb25JbmZvLCAndmlld2VyLnVzZXIuJywgb2JqZWN0SWQpLFxuICAgICAgICB9O1xuICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBwYXJzZUdyYXBoUUxTY2hlbWEuaGFuZGxlRXJyb3IoZSk7XG4gICAgICB9XG4gICAgfSxcbiAgfSk7XG5cbiAgcGFyc2VHcmFwaFFMU2NoZW1hLmFkZEdyYXBoUUxUeXBlKGxvZ0luTXV0YXRpb24uYXJncy5pbnB1dC50eXBlLm9mVHlwZSwgdHJ1ZSwgdHJ1ZSk7XG4gIHBhcnNlR3JhcGhRTFNjaGVtYS5hZGRHcmFwaFFMVHlwZShsb2dJbk11dGF0aW9uLnR5cGUsIHRydWUsIHRydWUpO1xuICBwYXJzZUdyYXBoUUxTY2hlbWEuYWRkR3JhcGhRTE11dGF0aW9uKCdsb2dJbicsIGxvZ0luTXV0YXRpb24sIHRydWUsIHRydWUpO1xuXG4gIGNvbnN0IGxvZ091dE11dGF0aW9uID0gbXV0YXRpb25XaXRoQ2xpZW50TXV0YXRpb25JZCh7XG4gICAgbmFtZTogJ0xvZ091dCcsXG4gICAgZGVzY3JpcHRpb246ICdUaGUgbG9nT3V0IG11dGF0aW9uIGNhbiBiZSB1c2VkIHRvIGxvZyBvdXQgYW4gZXhpc3RpbmcgdXNlci4nLFxuICAgIG91dHB1dEZpZWxkczoge1xuICAgICAgb2s6IHtcbiAgICAgICAgZGVzY3JpcHRpb246IFwiSXQncyBhbHdheXMgdHJ1ZS5cIixcbiAgICAgICAgdHlwZTogbmV3IEdyYXBoUUxOb25OdWxsKEdyYXBoUUxCb29sZWFuKSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBtdXRhdGVBbmRHZXRQYXlsb2FkOiBhc3luYyAoX2FyZ3MsIGNvbnRleHQpID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHsgY29uZmlnLCBhdXRoLCBpbmZvIH0gPSBjb250ZXh0O1xuXG4gICAgICAgIGF3YWl0IHVzZXJzUm91dGVyLmhhbmRsZUxvZ091dCh7XG4gICAgICAgICAgY29uZmlnLFxuICAgICAgICAgIGF1dGgsXG4gICAgICAgICAgaW5mbyxcbiAgICAgICAgfSk7XG5cbiAgICAgICAgcmV0dXJuIHsgb2s6IHRydWUgfTtcbiAgICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgcGFyc2VHcmFwaFFMU2NoZW1hLmhhbmRsZUVycm9yKGUpO1xuICAgICAgfVxuICAgIH0sXG4gIH0pO1xuXG4gIHBhcnNlR3JhcGhRTFNjaGVtYS5hZGRHcmFwaFFMVHlwZShsb2dPdXRNdXRhdGlvbi5hcmdzLmlucHV0LnR5cGUub2ZUeXBlLCB0cnVlLCB0cnVlKTtcbiAgcGFyc2VHcmFwaFFMU2NoZW1hLmFkZEdyYXBoUUxUeXBlKGxvZ091dE11dGF0aW9uLnR5cGUsIHRydWUsIHRydWUpO1xuICBwYXJzZUdyYXBoUUxTY2hlbWEuYWRkR3JhcGhRTE11dGF0aW9uKCdsb2dPdXQnLCBsb2dPdXRNdXRhdGlvbiwgdHJ1ZSwgdHJ1ZSk7XG5cbiAgY29uc3QgcmVzZXRQYXNzd29yZE11dGF0aW9uID0gbXV0YXRpb25XaXRoQ2xpZW50TXV0YXRpb25JZCh7XG4gICAgbmFtZTogJ1Jlc2V0UGFzc3dvcmQnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ1RoZSByZXNldFBhc3N3b3JkIG11dGF0aW9uIGNhbiBiZSB1c2VkIHRvIHJlc2V0IHRoZSBwYXNzd29yZCBvZiBhbiBleGlzdGluZyB1c2VyLicsXG4gICAgaW5wdXRGaWVsZHM6IHtcbiAgICAgIGVtYWlsOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uczogJ0VtYWlsIG9mIHRoZSB1c2VyIHRoYXQgc2hvdWxkIHJlY2VpdmUgdGhlIHJlc2V0IGVtYWlsJyxcbiAgICAgICAgdHlwZTogbmV3IEdyYXBoUUxOb25OdWxsKEdyYXBoUUxTdHJpbmcpLFxuICAgICAgfSxcbiAgICB9LFxuICAgIG91dHB1dEZpZWxkczoge1xuICAgICAgb2s6IHtcbiAgICAgICAgZGVzY3JpcHRpb246IFwiSXQncyBhbHdheXMgdHJ1ZS5cIixcbiAgICAgICAgdHlwZTogbmV3IEdyYXBoUUxOb25OdWxsKEdyYXBoUUxCb29sZWFuKSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBtdXRhdGVBbmRHZXRQYXlsb2FkOiBhc3luYyAoeyBlbWFpbCB9LCBjb250ZXh0KSA9PiB7XG4gICAgICBjb25zdCB7IGNvbmZpZywgYXV0aCwgaW5mbyB9ID0gY29udGV4dDtcblxuICAgICAgYXdhaXQgdXNlcnNSb3V0ZXIuaGFuZGxlUmVzZXRSZXF1ZXN0KHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIGVtYWlsLFxuICAgICAgICB9LFxuICAgICAgICBjb25maWcsXG4gICAgICAgIGF1dGgsXG4gICAgICAgIGluZm8sXG4gICAgICB9KTtcblxuICAgICAgcmV0dXJuIHsgb2s6IHRydWUgfTtcbiAgICB9LFxuICB9KTtcblxuICBwYXJzZUdyYXBoUUxTY2hlbWEuYWRkR3JhcGhRTFR5cGUocmVzZXRQYXNzd29yZE11dGF0aW9uLmFyZ3MuaW5wdXQudHlwZS5vZlR5cGUsIHRydWUsIHRydWUpO1xuICBwYXJzZUdyYXBoUUxTY2hlbWEuYWRkR3JhcGhRTFR5cGUocmVzZXRQYXNzd29yZE11dGF0aW9uLnR5cGUsIHRydWUsIHRydWUpO1xuICBwYXJzZUdyYXBoUUxTY2hlbWEuYWRkR3JhcGhRTE11dGF0aW9uKCdyZXNldFBhc3N3b3JkJywgcmVzZXRQYXNzd29yZE11dGF0aW9uLCB0cnVlLCB0cnVlKTtcblxuICBjb25zdCBjb25maXJtUmVzZXRQYXNzd29yZE11dGF0aW9uID0gbXV0YXRpb25XaXRoQ2xpZW50TXV0YXRpb25JZCh7XG4gICAgbmFtZTogJ0NvbmZpcm1SZXNldFBhc3N3b3JkJyxcbiAgICBkZXNjcmlwdGlvbjpcbiAgICAgICdUaGUgY29uZmlybVJlc2V0UGFzc3dvcmQgbXV0YXRpb24gY2FuIGJlIHVzZWQgdG8gcmVzZXQgdGhlIHBhc3N3b3JkIG9mIGFuIGV4aXN0aW5nIHVzZXIuJyxcbiAgICBpbnB1dEZpZWxkczoge1xuICAgICAgdXNlcm5hbWU6IHtcbiAgICAgICAgZGVzY3JpcHRpb25zOiAnVXNlcm5hbWUgb2YgdGhlIHVzZXIgdGhhdCBoYXZlIHJlY2VpdmVkIHRoZSByZXNldCBlbWFpbCcsXG4gICAgICAgIHR5cGU6IG5ldyBHcmFwaFFMTm9uTnVsbChHcmFwaFFMU3RyaW5nKSxcbiAgICAgIH0sXG4gICAgICBwYXNzd29yZDoge1xuICAgICAgICBkZXNjcmlwdGlvbnM6ICdOZXcgcGFzc3dvcmQgb2YgdGhlIHVzZXInLFxuICAgICAgICB0eXBlOiBuZXcgR3JhcGhRTE5vbk51bGwoR3JhcGhRTFN0cmluZyksXG4gICAgICB9LFxuICAgICAgdG9rZW46IHtcbiAgICAgICAgZGVzY3JpcHRpb25zOiAnUmVzZXQgdG9rZW4gdGhhdCB3YXMgZW1haWxlZCB0byB0aGUgdXNlcicsXG4gICAgICAgIHR5cGU6IG5ldyBHcmFwaFFMTm9uTnVsbChHcmFwaFFMU3RyaW5nKSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBvdXRwdXRGaWVsZHM6IHtcbiAgICAgIG9rOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiBcIkl0J3MgYWx3YXlzIHRydWUuXCIsXG4gICAgICAgIHR5cGU6IG5ldyBHcmFwaFFMTm9uTnVsbChHcmFwaFFMQm9vbGVhbiksXG4gICAgICB9LFxuICAgIH0sXG4gICAgbXV0YXRlQW5kR2V0UGF5bG9hZDogYXN5bmMgKHsgdXNlcm5hbWUsIHBhc3N3b3JkLCB0b2tlbiB9LCBjb250ZXh0KSA9PiB7XG4gICAgICBjb25zdCB7IGNvbmZpZyB9ID0gY29udGV4dDtcbiAgICAgIGlmICghdXNlcm5hbWUpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLlVTRVJOQU1FX01JU1NJTkcsICd5b3UgbXVzdCBwcm92aWRlIGEgdXNlcm5hbWUnKTtcbiAgICAgIH1cbiAgICAgIGlmICghcGFzc3dvcmQpIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLlBBU1NXT1JEX01JU1NJTkcsICd5b3UgbXVzdCBwcm92aWRlIGEgcGFzc3dvcmQnKTtcbiAgICAgIH1cbiAgICAgIGlmICghdG9rZW4pIHtcbiAgICAgICAgdGhyb3cgbmV3IFBhcnNlLkVycm9yKFBhcnNlLkVycm9yLk9USEVSX0NBVVNFLCAneW91IG11c3QgcHJvdmlkZSBhIHRva2VuJyk7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IHVzZXJDb250cm9sbGVyID0gY29uZmlnLnVzZXJDb250cm9sbGVyO1xuICAgICAgYXdhaXQgdXNlckNvbnRyb2xsZXIudXBkYXRlUGFzc3dvcmQodXNlcm5hbWUsIHRva2VuLCBwYXNzd29yZCk7XG4gICAgICByZXR1cm4geyBvazogdHJ1ZSB9O1xuICAgIH0sXG4gIH0pO1xuXG4gIHBhcnNlR3JhcGhRTFNjaGVtYS5hZGRHcmFwaFFMVHlwZShcbiAgICBjb25maXJtUmVzZXRQYXNzd29yZE11dGF0aW9uLmFyZ3MuaW5wdXQudHlwZS5vZlR5cGUsXG4gICAgdHJ1ZSxcbiAgICB0cnVlXG4gICk7XG4gIHBhcnNlR3JhcGhRTFNjaGVtYS5hZGRHcmFwaFFMVHlwZShjb25maXJtUmVzZXRQYXNzd29yZE11dGF0aW9uLnR5cGUsIHRydWUsIHRydWUpO1xuICBwYXJzZUdyYXBoUUxTY2hlbWEuYWRkR3JhcGhRTE11dGF0aW9uKFxuICAgICdjb25maXJtUmVzZXRQYXNzd29yZCcsXG4gICAgY29uZmlybVJlc2V0UGFzc3dvcmRNdXRhdGlvbixcbiAgICB0cnVlLFxuICAgIHRydWVcbiAgKTtcblxuICBjb25zdCBzZW5kVmVyaWZpY2F0aW9uRW1haWxNdXRhdGlvbiA9IG11dGF0aW9uV2l0aENsaWVudE11dGF0aW9uSWQoe1xuICAgIG5hbWU6ICdTZW5kVmVyaWZpY2F0aW9uRW1haWwnLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ1RoZSBzZW5kVmVyaWZpY2F0aW9uRW1haWwgbXV0YXRpb24gY2FuIGJlIHVzZWQgdG8gc2VuZCB0aGUgdmVyaWZpY2F0aW9uIGVtYWlsIGFnYWluLicsXG4gICAgaW5wdXRGaWVsZHM6IHtcbiAgICAgIGVtYWlsOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uczogJ0VtYWlsIG9mIHRoZSB1c2VyIHRoYXQgc2hvdWxkIHJlY2VpdmUgdGhlIHZlcmlmaWNhdGlvbiBlbWFpbCcsXG4gICAgICAgIHR5cGU6IG5ldyBHcmFwaFFMTm9uTnVsbChHcmFwaFFMU3RyaW5nKSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBvdXRwdXRGaWVsZHM6IHtcbiAgICAgIG9rOiB7XG4gICAgICAgIGRlc2NyaXB0aW9uOiBcIkl0J3MgYWx3YXlzIHRydWUuXCIsXG4gICAgICAgIHR5cGU6IG5ldyBHcmFwaFFMTm9uTnVsbChHcmFwaFFMQm9vbGVhbiksXG4gICAgICB9LFxuICAgIH0sXG4gICAgbXV0YXRlQW5kR2V0UGF5bG9hZDogYXN5bmMgKHsgZW1haWwgfSwgY29udGV4dCkgPT4ge1xuICAgICAgdHJ5IHtcbiAgICAgICAgY29uc3QgeyBjb25maWcsIGF1dGgsIGluZm8gfSA9IGNvbnRleHQ7XG5cbiAgICAgICAgYXdhaXQgdXNlcnNSb3V0ZXIuaGFuZGxlVmVyaWZpY2F0aW9uRW1haWxSZXF1ZXN0KHtcbiAgICAgICAgICBib2R5OiB7XG4gICAgICAgICAgICBlbWFpbCxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGNvbmZpZyxcbiAgICAgICAgICBhdXRoLFxuICAgICAgICAgIGluZm8sXG4gICAgICAgIH0pO1xuXG4gICAgICAgIHJldHVybiB7IG9rOiB0cnVlIH07XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHBhcnNlR3JhcGhRTFNjaGVtYS5oYW5kbGVFcnJvcihlKTtcbiAgICAgIH1cbiAgICB9LFxuICB9KTtcblxuICBwYXJzZUdyYXBoUUxTY2hlbWEuYWRkR3JhcGhRTFR5cGUoXG4gICAgc2VuZFZlcmlmaWNhdGlvbkVtYWlsTXV0YXRpb24uYXJncy5pbnB1dC50eXBlLm9mVHlwZSxcbiAgICB0cnVlLFxuICAgIHRydWVcbiAgKTtcbiAgcGFyc2VHcmFwaFFMU2NoZW1hLmFkZEdyYXBoUUxUeXBlKHNlbmRWZXJpZmljYXRpb25FbWFpbE11dGF0aW9uLnR5cGUsIHRydWUsIHRydWUpO1xuICBwYXJzZUdyYXBoUUxTY2hlbWEuYWRkR3JhcGhRTE11dGF0aW9uKFxuICAgICdzZW5kVmVyaWZpY2F0aW9uRW1haWwnLFxuICAgIHNlbmRWZXJpZmljYXRpb25FbWFpbE11dGF0aW9uLFxuICAgIHRydWUsXG4gICAgdHJ1ZVxuICApO1xufTtcblxuZXhwb3J0IHsgbG9hZCB9O1xuIl19