"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ParseLiveQueryServer = void 0;

var _tv = _interopRequireDefault(require("tv4"));

var _node = _interopRequireDefault(require("parse/node"));

var _Subscription = require("./Subscription");

var _Client = require("./Client");

var _ParseWebSocketServer = require("./ParseWebSocketServer");

var _logger = _interopRequireDefault(require("../logger"));

var _RequestSchema = _interopRequireDefault(require("./RequestSchema"));

var _QueryTools = require("./QueryTools");

var _ParsePubSub = require("./ParsePubSub");

var _SchemaController = _interopRequireDefault(require("../Controllers/SchemaController"));

var _lodash = _interopRequireDefault(require("lodash"));

var _uuid = require("uuid");

var _triggers = require("../triggers");

var _Auth = require("../Auth");

var _Controllers = require("../Controllers");

var _lruCache = _interopRequireDefault(require("lru-cache"));

var _UsersRouter = _interopRequireDefault(require("../Routers/UsersRouter"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

class ParseLiveQueryServer {
  // className -> (queryHash -> subscription)
  // The subscriber we use to get object update from publisher
  constructor(server, config = {}, parseServerConfig = {}) {
    this.server = server;
    this.clients = new Map();
    this.subscriptions = new Map();
    this.config = config;
    config.appId = config.appId || _node.default.applicationId;
    config.masterKey = config.masterKey || _node.default.masterKey; // Store keys, convert obj to map

    const keyPairs = config.keyPairs || {};
    this.keyPairs = new Map();

    for (const key of Object.keys(keyPairs)) {
      this.keyPairs.set(key, keyPairs[key]);
    }

    _logger.default.verbose('Support key pairs', this.keyPairs); // Initialize Parse


    _node.default.Object.disableSingleInstance();

    const serverURL = config.serverURL || _node.default.serverURL;
    _node.default.serverURL = serverURL;

    _node.default.initialize(config.appId, _node.default.javaScriptKey, config.masterKey); // The cache controller is a proper cache controller
    // with access to User and Roles


    this.cacheController = (0, _Controllers.getCacheController)(parseServerConfig);
    config.cacheTimeout = config.cacheTimeout || 5 * 1000; // 5s
    // This auth cache stores the promises for each auth resolution.
    // The main benefit is to be able to reuse the same user / session token resolution.

    this.authCache = new _lruCache.default({
      max: 500,
      // 500 concurrent
      maxAge: config.cacheTimeout
    }); // Initialize websocket server

    this.parseWebSocketServer = new _ParseWebSocketServer.ParseWebSocketServer(server, parseWebsocket => this._onConnect(parseWebsocket), config); // Initialize subscriber

    this.subscriber = _ParsePubSub.ParsePubSub.createSubscriber(config);
    this.subscriber.subscribe(_node.default.applicationId + 'afterSave');
    this.subscriber.subscribe(_node.default.applicationId + 'afterDelete'); // Register message handler for subscriber. When publisher get messages, it will publish message
    // to the subscribers and the handler will be called.

    this.subscriber.on('message', (channel, messageStr) => {
      _logger.default.verbose('Subscribe message %j', messageStr);

      let message;

      try {
        message = JSON.parse(messageStr);
      } catch (e) {
        _logger.default.error('unable to parse message', messageStr, e);

        return;
      }

      this._inflateParseObject(message);

      if (channel === _node.default.applicationId + 'afterSave') {
        this._onAfterSave(message);
      } else if (channel === _node.default.applicationId + 'afterDelete') {
        this._onAfterDelete(message);
      } else {
        _logger.default.error('Get message %s from unknown channel %j', message, channel);
      }
    });
  } // Message is the JSON object from publisher. Message.currentParseObject is the ParseObject JSON after changes.
  // Message.originalParseObject is the original ParseObject JSON.


  _inflateParseObject(message) {
    // Inflate merged object
    const currentParseObject = message.currentParseObject;

    _UsersRouter.default.removeHiddenProperties(currentParseObject);

    let className = currentParseObject.className;
    let parseObject = new _node.default.Object(className);

    parseObject._finishFetch(currentParseObject);

    message.currentParseObject = parseObject; // Inflate original object

    const originalParseObject = message.originalParseObject;

    if (originalParseObject) {
      _UsersRouter.default.removeHiddenProperties(originalParseObject);

      className = originalParseObject.className;
      parseObject = new _node.default.Object(className);

      parseObject._finishFetch(originalParseObject);

      message.originalParseObject = parseObject;
    }
  } // Message is the JSON object from publisher after inflated. Message.currentParseObject is the ParseObject after changes.
  // Message.originalParseObject is the original ParseObject.


  async _onAfterDelete(message) {
    _logger.default.verbose(_node.default.applicationId + 'afterDelete is triggered');

    let deletedParseObject = message.currentParseObject.toJSON();
    const classLevelPermissions = message.classLevelPermissions;
    const className = deletedParseObject.className;

    _logger.default.verbose('ClassName: %j | ObjectId: %s', className, deletedParseObject.id);

    _logger.default.verbose('Current client number : %d', this.clients.size);

    const classSubscriptions = this.subscriptions.get(className);

    if (typeof classSubscriptions === 'undefined') {
      _logger.default.debug('Can not find subscriptions under this class ' + className);

      return;
    }

    for (const subscription of classSubscriptions.values()) {
      const isSubscriptionMatched = this._matchesSubscription(deletedParseObject, subscription);

      if (!isSubscriptionMatched) {
        continue;
      }

      for (const [clientId, requestIds] of _lodash.default.entries(subscription.clientRequestIds)) {
        const client = this.clients.get(clientId);

        if (typeof client === 'undefined') {
          continue;
        }

        requestIds.forEach(async requestId => {
          const acl = message.currentParseObject.getACL(); // Check CLP

          const op = this._getCLPOperation(subscription.query);

          let res = {};

          try {
            await this._matchesCLP(classLevelPermissions, message.currentParseObject, client, requestId, op);
            const isMatched = await this._matchesACL(acl, client, requestId);

            if (!isMatched) {
              return null;
            }

            res = {
              event: 'delete',
              sessionToken: client.sessionToken,
              object: deletedParseObject,
              clients: this.clients.size,
              subscriptions: this.subscriptions.size,
              useMasterKey: client.hasMasterKey,
              installationId: client.installationId,
              sendEvent: true
            };
            const trigger = (0, _triggers.getTrigger)(className, 'afterEvent', _node.default.applicationId);

            if (trigger) {
              const auth = await this.getAuthFromClient(client, requestId);

              if (auth && auth.user) {
                res.user = auth.user;
              }

              if (res.object) {
                res.object = _node.default.Object.fromJSON(res.object);
              }

              await (0, _triggers.runTrigger)(trigger, `afterEvent.${className}`, res, auth);
            }

            if (!res.sendEvent) {
              return;
            }

            if (res.object && typeof res.object.toJSON === 'function') {
              deletedParseObject = res.object.toJSON();
              deletedParseObject.className = className;
            }

            client.pushDelete(requestId, deletedParseObject);
          } catch (error) {
            _Client.Client.pushError(client.parseWebSocket, error.code || 141, error.message || error, false, requestId);

            _logger.default.error(`Failed running afterLiveQueryEvent on class ${className} for event ${res.event} with session ${res.sessionToken} with:\n Error: ` + JSON.stringify(error));
          }
        });
      }
    }
  } // Message is the JSON object from publisher after inflated. Message.currentParseObject is the ParseObject after changes.
  // Message.originalParseObject is the original ParseObject.


  async _onAfterSave(message) {
    _logger.default.verbose(_node.default.applicationId + 'afterSave is triggered');

    let originalParseObject = null;

    if (message.originalParseObject) {
      originalParseObject = message.originalParseObject.toJSON();
    }

    const classLevelPermissions = message.classLevelPermissions;
    let currentParseObject = message.currentParseObject.toJSON();
    const className = currentParseObject.className;

    _logger.default.verbose('ClassName: %s | ObjectId: %s', className, currentParseObject.id);

    _logger.default.verbose('Current client number : %d', this.clients.size);

    const classSubscriptions = this.subscriptions.get(className);

    if (typeof classSubscriptions === 'undefined') {
      _logger.default.debug('Can not find subscriptions under this class ' + className);

      return;
    }

    for (const subscription of classSubscriptions.values()) {
      const isOriginalSubscriptionMatched = this._matchesSubscription(originalParseObject, subscription);

      const isCurrentSubscriptionMatched = this._matchesSubscription(currentParseObject, subscription);

      for (const [clientId, requestIds] of _lodash.default.entries(subscription.clientRequestIds)) {
        const client = this.clients.get(clientId);

        if (typeof client === 'undefined') {
          continue;
        }

        requestIds.forEach(async requestId => {
          // Set orignal ParseObject ACL checking promise, if the object does not match
          // subscription, we do not need to check ACL
          let originalACLCheckingPromise;

          if (!isOriginalSubscriptionMatched) {
            originalACLCheckingPromise = Promise.resolve(false);
          } else {
            let originalACL;

            if (message.originalParseObject) {
              originalACL = message.originalParseObject.getACL();
            }

            originalACLCheckingPromise = this._matchesACL(originalACL, client, requestId);
          } // Set current ParseObject ACL checking promise, if the object does not match
          // subscription, we do not need to check ACL


          let currentACLCheckingPromise;
          let res = {};

          if (!isCurrentSubscriptionMatched) {
            currentACLCheckingPromise = Promise.resolve(false);
          } else {
            const currentACL = message.currentParseObject.getACL();
            currentACLCheckingPromise = this._matchesACL(currentACL, client, requestId);
          }

          try {
            const op = this._getCLPOperation(subscription.query);

            await this._matchesCLP(classLevelPermissions, message.currentParseObject, client, requestId, op);
            const [isOriginalMatched, isCurrentMatched] = await Promise.all([originalACLCheckingPromise, currentACLCheckingPromise]);

            _logger.default.verbose('Original %j | Current %j | Match: %s, %s, %s, %s | Query: %s', originalParseObject, currentParseObject, isOriginalSubscriptionMatched, isCurrentSubscriptionMatched, isOriginalMatched, isCurrentMatched, subscription.hash); // Decide event type


            let type;

            if (isOriginalMatched && isCurrentMatched) {
              type = 'update';
            } else if (isOriginalMatched && !isCurrentMatched) {
              type = 'leave';
            } else if (!isOriginalMatched && isCurrentMatched) {
              if (originalParseObject) {
                type = 'enter';
              } else {
                type = 'create';
              }
            } else {
              return null;
            }

            res = {
              event: type,
              sessionToken: client.sessionToken,
              object: currentParseObject,
              original: originalParseObject,
              clients: this.clients.size,
              subscriptions: this.subscriptions.size,
              useMasterKey: client.hasMasterKey,
              installationId: client.installationId,
              sendEvent: true
            };
            const trigger = (0, _triggers.getTrigger)(className, 'afterEvent', _node.default.applicationId);

            if (trigger) {
              if (res.object) {
                res.object = _node.default.Object.fromJSON(res.object);
              }

              if (res.original) {
                res.original = _node.default.Object.fromJSON(res.original);
              }

              const auth = await this.getAuthFromClient(client, requestId);

              if (auth && auth.user) {
                res.user = auth.user;
              }

              await (0, _triggers.runTrigger)(trigger, `afterEvent.${className}`, res, auth);
            }

            if (!res.sendEvent) {
              return;
            }

            if (res.object && typeof res.object.toJSON === 'function') {
              currentParseObject = res.object.toJSON();
              currentParseObject.className = res.object.className || className;
            }

            if (res.original && typeof res.original.toJSON === 'function') {
              originalParseObject = res.original.toJSON();
              originalParseObject.className = res.original.className || className;
            }

            const functionName = 'push' + res.event.charAt(0).toUpperCase() + res.event.slice(1);

            if (client[functionName]) {
              client[functionName](requestId, currentParseObject, originalParseObject);
            }
          } catch (error) {
            _Client.Client.pushError(client.parseWebSocket, error.code || 141, error.message || error, false, requestId);

            _logger.default.error(`Failed running afterLiveQueryEvent on class ${className} for event ${res.event} with session ${res.sessionToken} with:\n Error: ` + JSON.stringify(error));
          }
        });
      }
    }
  }

  _onConnect(parseWebsocket) {
    parseWebsocket.on('message', request => {
      if (typeof request === 'string') {
        try {
          request = JSON.parse(request);
        } catch (e) {
          _logger.default.error('unable to parse request', request, e);

          return;
        }
      }

      _logger.default.verbose('Request: %j', request); // Check whether this request is a valid request, return error directly if not


      if (!_tv.default.validate(request, _RequestSchema.default['general']) || !_tv.default.validate(request, _RequestSchema.default[request.op])) {
        _Client.Client.pushError(parseWebsocket, 1, _tv.default.error.message);

        _logger.default.error('Connect message error %s', _tv.default.error.message);

        return;
      }

      switch (request.op) {
        case 'connect':
          this._handleConnect(parseWebsocket, request);

          break;

        case 'subscribe':
          this._handleSubscribe(parseWebsocket, request);

          break;

        case 'update':
          this._handleUpdateSubscription(parseWebsocket, request);

          break;

        case 'unsubscribe':
          this._handleUnsubscribe(parseWebsocket, request);

          break;

        default:
          _Client.Client.pushError(parseWebsocket, 3, 'Get unknown operation');

          _logger.default.error('Get unknown operation', request.op);

      }
    });
    parseWebsocket.on('disconnect', () => {
      _logger.default.info(`Client disconnect: ${parseWebsocket.clientId}`);

      const clientId = parseWebsocket.clientId;

      if (!this.clients.has(clientId)) {
        (0, _triggers.runLiveQueryEventHandlers)({
          event: 'ws_disconnect_error',
          clients: this.clients.size,
          subscriptions: this.subscriptions.size,
          error: `Unable to find client ${clientId}`
        });

        _logger.default.error(`Can not find client ${clientId} on disconnect`);

        return;
      } // Delete client


      const client = this.clients.get(clientId);
      this.clients.delete(clientId); // Delete client from subscriptions

      for (const [requestId, subscriptionInfo] of _lodash.default.entries(client.subscriptionInfos)) {
        const subscription = subscriptionInfo.subscription;
        subscription.deleteClientSubscription(clientId, requestId); // If there is no client which is subscribing this subscription, remove it from subscriptions

        const classSubscriptions = this.subscriptions.get(subscription.className);

        if (!subscription.hasSubscribingClient()) {
          classSubscriptions.delete(subscription.hash);
        } // If there is no subscriptions under this class, remove it from subscriptions


        if (classSubscriptions.size === 0) {
          this.subscriptions.delete(subscription.className);
        }
      }

      _logger.default.verbose('Current clients %d', this.clients.size);

      _logger.default.verbose('Current subscriptions %d', this.subscriptions.size);

      (0, _triggers.runLiveQueryEventHandlers)({
        event: 'ws_disconnect',
        clients: this.clients.size,
        subscriptions: this.subscriptions.size,
        useMasterKey: client.hasMasterKey,
        installationId: client.installationId,
        sessionToken: client.sessionToken
      });
    });
    (0, _triggers.runLiveQueryEventHandlers)({
      event: 'ws_connect',
      clients: this.clients.size,
      subscriptions: this.subscriptions.size
    });
  }

  _matchesSubscription(parseObject, subscription) {
    // Object is undefined or null, not match
    if (!parseObject) {
      return false;
    }

    return (0, _QueryTools.matchesQuery)(parseObject, subscription.query);
  }

  getAuthForSessionToken(sessionToken) {
    if (!sessionToken) {
      return Promise.resolve({});
    }

    const fromCache = this.authCache.get(sessionToken);

    if (fromCache) {
      return fromCache;
    }

    const authPromise = (0, _Auth.getAuthForSessionToken)({
      cacheController: this.cacheController,
      sessionToken: sessionToken
    }).then(auth => {
      return {
        auth,
        userId: auth && auth.user && auth.user.id
      };
    }).catch(error => {
      // There was an error with the session token
      const result = {};

      if (error && error.code === _node.default.Error.INVALID_SESSION_TOKEN) {
        result.error = error;
        this.authCache.set(sessionToken, Promise.resolve(result), this.config.cacheTimeout);
      } else {
        this.authCache.del(sessionToken);
      }

      return result;
    });
    this.authCache.set(sessionToken, authPromise);
    return authPromise;
  }

  async _matchesCLP(classLevelPermissions, object, client, requestId, op) {
    // try to match on user first, less expensive than with roles
    const subscriptionInfo = client.getSubscriptionInfo(requestId);
    const aclGroup = ['*'];
    let userId;

    if (typeof subscriptionInfo !== 'undefined') {
      const {
        userId
      } = await this.getAuthForSessionToken(subscriptionInfo.sessionToken);

      if (userId) {
        aclGroup.push(userId);
      }
    }

    try {
      await _SchemaController.default.validatePermission(classLevelPermissions, object.className, aclGroup, op);
      return true;
    } catch (e) {
      _logger.default.verbose(`Failed matching CLP for ${object.id} ${userId} ${e}`);

      return false;
    } // TODO: handle roles permissions
    // Object.keys(classLevelPermissions).forEach((key) => {
    //   const perm = classLevelPermissions[key];
    //   Object.keys(perm).forEach((key) => {
    //     if (key.indexOf('role'))
    //   });
    // })
    // // it's rejected here, check the roles
    // var rolesQuery = new Parse.Query(Parse.Role);
    // rolesQuery.equalTo("users", user);
    // return rolesQuery.find({useMasterKey:true});

  }

  _getCLPOperation(query) {
    return typeof query === 'object' && Object.keys(query).length == 1 && typeof query.objectId === 'string' ? 'get' : 'find';
  }

  async _verifyACL(acl, token) {
    if (!token) {
      return false;
    }

    const {
      auth,
      userId
    } = await this.getAuthForSessionToken(token); // Getting the session token failed
    // This means that no additional auth is available
    // At this point, just bail out as no additional visibility can be inferred.

    if (!auth || !userId) {
      return false;
    }

    const isSubscriptionSessionTokenMatched = acl.getReadAccess(userId);

    if (isSubscriptionSessionTokenMatched) {
      return true;
    } // Check if the user has any roles that match the ACL


    return Promise.resolve().then(async () => {
      // Resolve false right away if the acl doesn't have any roles
      const acl_has_roles = Object.keys(acl.permissionsById).some(key => key.startsWith('role:'));

      if (!acl_has_roles) {
        return false;
      }

      const roleNames = await auth.getUserRoles(); // Finally, see if any of the user's roles allow them read access

      for (const role of roleNames) {
        // We use getReadAccess as `role` is in the form `role:roleName`
        if (acl.getReadAccess(role)) {
          return true;
        }
      }

      return false;
    }).catch(() => {
      return false;
    });
  }

  async getAuthFromClient(client, requestId, sessionToken) {
    const getSessionFromClient = () => {
      const subscriptionInfo = client.getSubscriptionInfo(requestId);

      if (typeof subscriptionInfo === 'undefined') {
        return client.sessionToken;
      }

      return subscriptionInfo.sessionToken || client.sessionToken;
    };

    if (!sessionToken) {
      sessionToken = getSessionFromClient();
    }

    if (!sessionToken) {
      return;
    }

    const {
      auth
    } = await this.getAuthForSessionToken(sessionToken);
    return auth;
  }

  async _matchesACL(acl, client, requestId) {
    // Return true directly if ACL isn't present, ACL is public read, or client has master key
    if (!acl || acl.getPublicReadAccess() || client.hasMasterKey) {
      return true;
    } // Check subscription sessionToken matches ACL first


    const subscriptionInfo = client.getSubscriptionInfo(requestId);

    if (typeof subscriptionInfo === 'undefined') {
      return false;
    }

    const subscriptionToken = subscriptionInfo.sessionToken;
    const clientSessionToken = client.sessionToken;

    if (await this._verifyACL(acl, subscriptionToken)) {
      return true;
    }

    if (await this._verifyACL(acl, clientSessionToken)) {
      return true;
    }

    return false;
  }

  async _handleConnect(parseWebsocket, request) {
    if (!this._validateKeys(request, this.keyPairs)) {
      _Client.Client.pushError(parseWebsocket, 4, 'Key in request is not valid');

      _logger.default.error('Key in request is not valid');

      return;
    }

    const hasMasterKey = this._hasMasterKey(request, this.keyPairs);

    const clientId = (0, _uuid.v4)();
    const client = new _Client.Client(clientId, parseWebsocket, hasMasterKey, request.sessionToken, request.installationId);

    try {
      const req = {
        client,
        event: 'connect',
        clients: this.clients.size,
        subscriptions: this.subscriptions.size,
        sessionToken: request.sessionToken,
        useMasterKey: client.hasMasterKey,
        installationId: request.installationId
      };
      const trigger = (0, _triggers.getTrigger)('@Connect', 'beforeConnect', _node.default.applicationId);

      if (trigger) {
        const auth = await this.getAuthFromClient(client, request.requestId, req.sessionToken);

        if (auth && auth.user) {
          req.user = auth.user;
        }

        await (0, _triggers.runTrigger)(trigger, `beforeConnect.@Connect`, req, auth);
      }

      parseWebsocket.clientId = clientId;
      this.clients.set(parseWebsocket.clientId, client);

      _logger.default.info(`Create new client: ${parseWebsocket.clientId}`);

      client.pushConnect();
      (0, _triggers.runLiveQueryEventHandlers)(req);
    } catch (error) {
      _Client.Client.pushError(parseWebsocket, error.code || 141, error.message || error, false);

      _logger.default.error(`Failed running beforeConnect for session ${request.sessionToken} with:\n Error: ` + JSON.stringify(error));
    }
  }

  _hasMasterKey(request, validKeyPairs) {
    if (!validKeyPairs || validKeyPairs.size == 0 || !validKeyPairs.has('masterKey')) {
      return false;
    }

    if (!request || !Object.prototype.hasOwnProperty.call(request, 'masterKey')) {
      return false;
    }

    return request.masterKey === validKeyPairs.get('masterKey');
  }

  _validateKeys(request, validKeyPairs) {
    if (!validKeyPairs || validKeyPairs.size == 0) {
      return true;
    }

    let isValid = false;

    for (const [key, secret] of validKeyPairs) {
      if (!request[key] || request[key] !== secret) {
        continue;
      }

      isValid = true;
      break;
    }

    return isValid;
  }

  async _handleSubscribe(parseWebsocket, request) {
    // If we can not find this client, return error to client
    if (!Object.prototype.hasOwnProperty.call(parseWebsocket, 'clientId')) {
      _Client.Client.pushError(parseWebsocket, 2, 'Can not find this client, make sure you connect to server before subscribing');

      _logger.default.error('Can not find this client, make sure you connect to server before subscribing');

      return;
    }

    const client = this.clients.get(parseWebsocket.clientId);
    const className = request.query.className;

    try {
      const trigger = (0, _triggers.getTrigger)(className, 'beforeSubscribe', _node.default.applicationId);

      if (trigger) {
        const auth = await this.getAuthFromClient(client, request.requestId, request.sessionToken);

        if (auth && auth.user) {
          request.user = auth.user;
        }

        const parseQuery = new _node.default.Query(className);
        parseQuery.withJSON(request.query);
        request.query = parseQuery;
        await (0, _triggers.runTrigger)(trigger, `beforeSubscribe.${className}`, request, auth);
        const query = request.query.toJSON();

        if (query.keys) {
          query.fields = query.keys.split(',');
        }

        request.query = query;
      } // Get subscription from subscriptions, create one if necessary


      const subscriptionHash = (0, _QueryTools.queryHash)(request.query); // Add className to subscriptions if necessary

      if (!this.subscriptions.has(className)) {
        this.subscriptions.set(className, new Map());
      }

      const classSubscriptions = this.subscriptions.get(className);
      let subscription;

      if (classSubscriptions.has(subscriptionHash)) {
        subscription = classSubscriptions.get(subscriptionHash);
      } else {
        subscription = new _Subscription.Subscription(className, request.query.where, subscriptionHash);
        classSubscriptions.set(subscriptionHash, subscription);
      } // Add subscriptionInfo to client


      const subscriptionInfo = {
        subscription: subscription
      }; // Add selected fields, sessionToken and installationId for this subscription if necessary

      if (request.query.fields) {
        subscriptionInfo.fields = request.query.fields;
      }

      if (request.sessionToken) {
        subscriptionInfo.sessionToken = request.sessionToken;
      }

      client.addSubscriptionInfo(request.requestId, subscriptionInfo); // Add clientId to subscription

      subscription.addClientSubscription(parseWebsocket.clientId, request.requestId);
      client.pushSubscribe(request.requestId);

      _logger.default.verbose(`Create client ${parseWebsocket.clientId} new subscription: ${request.requestId}`);

      _logger.default.verbose('Current client number: %d', this.clients.size);

      (0, _triggers.runLiveQueryEventHandlers)({
        client,
        event: 'subscribe',
        clients: this.clients.size,
        subscriptions: this.subscriptions.size,
        sessionToken: request.sessionToken,
        useMasterKey: client.hasMasterKey,
        installationId: client.installationId
      });
    } catch (e) {
      _Client.Client.pushError(parseWebsocket, e.code || 141, e.message || e, false, request.requestId);

      _logger.default.error(`Failed running beforeSubscribe on ${className} for session ${request.sessionToken} with:\n Error: ` + JSON.stringify(e));
    }
  }

  _handleUpdateSubscription(parseWebsocket, request) {
    this._handleUnsubscribe(parseWebsocket, request, false);

    this._handleSubscribe(parseWebsocket, request);
  }

  _handleUnsubscribe(parseWebsocket, request, notifyClient = true) {
    // If we can not find this client, return error to client
    if (!Object.prototype.hasOwnProperty.call(parseWebsocket, 'clientId')) {
      _Client.Client.pushError(parseWebsocket, 2, 'Can not find this client, make sure you connect to server before unsubscribing');

      _logger.default.error('Can not find this client, make sure you connect to server before unsubscribing');

      return;
    }

    const requestId = request.requestId;
    const client = this.clients.get(parseWebsocket.clientId);

    if (typeof client === 'undefined') {
      _Client.Client.pushError(parseWebsocket, 2, 'Cannot find client with clientId ' + parseWebsocket.clientId + '. Make sure you connect to live query server before unsubscribing.');

      _logger.default.error('Can not find this client ' + parseWebsocket.clientId);

      return;
    }

    const subscriptionInfo = client.getSubscriptionInfo(requestId);

    if (typeof subscriptionInfo === 'undefined') {
      _Client.Client.pushError(parseWebsocket, 2, 'Cannot find subscription with clientId ' + parseWebsocket.clientId + ' subscriptionId ' + requestId + '. Make sure you subscribe to live query server before unsubscribing.');

      _logger.default.error('Can not find subscription with clientId ' + parseWebsocket.clientId + ' subscriptionId ' + requestId);

      return;
    } // Remove subscription from client


    client.deleteSubscriptionInfo(requestId); // Remove client from subscription

    const subscription = subscriptionInfo.subscription;
    const className = subscription.className;
    subscription.deleteClientSubscription(parseWebsocket.clientId, requestId); // If there is no client which is subscribing this subscription, remove it from subscriptions

    const classSubscriptions = this.subscriptions.get(className);

    if (!subscription.hasSubscribingClient()) {
      classSubscriptions.delete(subscription.hash);
    } // If there is no subscriptions under this class, remove it from subscriptions


    if (classSubscriptions.size === 0) {
      this.subscriptions.delete(className);
    }

    (0, _triggers.runLiveQueryEventHandlers)({
      client,
      event: 'unsubscribe',
      clients: this.clients.size,
      subscriptions: this.subscriptions.size,
      sessionToken: subscriptionInfo.sessionToken,
      useMasterKey: client.hasMasterKey,
      installationId: client.installationId
    });

    if (!notifyClient) {
      return;
    }

    client.pushUnsubscribe(request.requestId);

    _logger.default.verbose(`Delete client: ${parseWebsocket.clientId} | subscription: ${request.requestId}`);
  }

}

exports.ParseLiveQueryServer = ParseLiveQueryServer;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9MaXZlUXVlcnkvUGFyc2VMaXZlUXVlcnlTZXJ2ZXIuanMiXSwibmFtZXMiOlsiUGFyc2VMaXZlUXVlcnlTZXJ2ZXIiLCJjb25zdHJ1Y3RvciIsInNlcnZlciIsImNvbmZpZyIsInBhcnNlU2VydmVyQ29uZmlnIiwiY2xpZW50cyIsIk1hcCIsInN1YnNjcmlwdGlvbnMiLCJhcHBJZCIsIlBhcnNlIiwiYXBwbGljYXRpb25JZCIsIm1hc3RlcktleSIsImtleVBhaXJzIiwia2V5IiwiT2JqZWN0Iiwia2V5cyIsInNldCIsImxvZ2dlciIsInZlcmJvc2UiLCJkaXNhYmxlU2luZ2xlSW5zdGFuY2UiLCJzZXJ2ZXJVUkwiLCJpbml0aWFsaXplIiwiamF2YVNjcmlwdEtleSIsImNhY2hlQ29udHJvbGxlciIsImNhY2hlVGltZW91dCIsImF1dGhDYWNoZSIsIkxSVSIsIm1heCIsIm1heEFnZSIsInBhcnNlV2ViU29ja2V0U2VydmVyIiwiUGFyc2VXZWJTb2NrZXRTZXJ2ZXIiLCJwYXJzZVdlYnNvY2tldCIsIl9vbkNvbm5lY3QiLCJzdWJzY3JpYmVyIiwiUGFyc2VQdWJTdWIiLCJjcmVhdGVTdWJzY3JpYmVyIiwic3Vic2NyaWJlIiwib24iLCJjaGFubmVsIiwibWVzc2FnZVN0ciIsIm1lc3NhZ2UiLCJKU09OIiwicGFyc2UiLCJlIiwiZXJyb3IiLCJfaW5mbGF0ZVBhcnNlT2JqZWN0IiwiX29uQWZ0ZXJTYXZlIiwiX29uQWZ0ZXJEZWxldGUiLCJjdXJyZW50UGFyc2VPYmplY3QiLCJVc2VyUm91dGVyIiwicmVtb3ZlSGlkZGVuUHJvcGVydGllcyIsImNsYXNzTmFtZSIsInBhcnNlT2JqZWN0IiwiX2ZpbmlzaEZldGNoIiwib3JpZ2luYWxQYXJzZU9iamVjdCIsImRlbGV0ZWRQYXJzZU9iamVjdCIsInRvSlNPTiIsImNsYXNzTGV2ZWxQZXJtaXNzaW9ucyIsImlkIiwic2l6ZSIsImNsYXNzU3Vic2NyaXB0aW9ucyIsImdldCIsImRlYnVnIiwic3Vic2NyaXB0aW9uIiwidmFsdWVzIiwiaXNTdWJzY3JpcHRpb25NYXRjaGVkIiwiX21hdGNoZXNTdWJzY3JpcHRpb24iLCJjbGllbnRJZCIsInJlcXVlc3RJZHMiLCJfIiwiZW50cmllcyIsImNsaWVudFJlcXVlc3RJZHMiLCJjbGllbnQiLCJmb3JFYWNoIiwicmVxdWVzdElkIiwiYWNsIiwiZ2V0QUNMIiwib3AiLCJfZ2V0Q0xQT3BlcmF0aW9uIiwicXVlcnkiLCJyZXMiLCJfbWF0Y2hlc0NMUCIsImlzTWF0Y2hlZCIsIl9tYXRjaGVzQUNMIiwiZXZlbnQiLCJzZXNzaW9uVG9rZW4iLCJvYmplY3QiLCJ1c2VNYXN0ZXJLZXkiLCJoYXNNYXN0ZXJLZXkiLCJpbnN0YWxsYXRpb25JZCIsInNlbmRFdmVudCIsInRyaWdnZXIiLCJhdXRoIiwiZ2V0QXV0aEZyb21DbGllbnQiLCJ1c2VyIiwiZnJvbUpTT04iLCJwdXNoRGVsZXRlIiwiQ2xpZW50IiwicHVzaEVycm9yIiwicGFyc2VXZWJTb2NrZXQiLCJjb2RlIiwic3RyaW5naWZ5IiwiaXNPcmlnaW5hbFN1YnNjcmlwdGlvbk1hdGNoZWQiLCJpc0N1cnJlbnRTdWJzY3JpcHRpb25NYXRjaGVkIiwib3JpZ2luYWxBQ0xDaGVja2luZ1Byb21pc2UiLCJQcm9taXNlIiwicmVzb2x2ZSIsIm9yaWdpbmFsQUNMIiwiY3VycmVudEFDTENoZWNraW5nUHJvbWlzZSIsImN1cnJlbnRBQ0wiLCJpc09yaWdpbmFsTWF0Y2hlZCIsImlzQ3VycmVudE1hdGNoZWQiLCJhbGwiLCJoYXNoIiwidHlwZSIsIm9yaWdpbmFsIiwiZnVuY3Rpb25OYW1lIiwiY2hhckF0IiwidG9VcHBlckNhc2UiLCJzbGljZSIsInJlcXVlc3QiLCJ0djQiLCJ2YWxpZGF0ZSIsIlJlcXVlc3RTY2hlbWEiLCJfaGFuZGxlQ29ubmVjdCIsIl9oYW5kbGVTdWJzY3JpYmUiLCJfaGFuZGxlVXBkYXRlU3Vic2NyaXB0aW9uIiwiX2hhbmRsZVVuc3Vic2NyaWJlIiwiaW5mbyIsImhhcyIsImRlbGV0ZSIsInN1YnNjcmlwdGlvbkluZm8iLCJzdWJzY3JpcHRpb25JbmZvcyIsImRlbGV0ZUNsaWVudFN1YnNjcmlwdGlvbiIsImhhc1N1YnNjcmliaW5nQ2xpZW50IiwiZ2V0QXV0aEZvclNlc3Npb25Ub2tlbiIsImZyb21DYWNoZSIsImF1dGhQcm9taXNlIiwidGhlbiIsInVzZXJJZCIsImNhdGNoIiwicmVzdWx0IiwiRXJyb3IiLCJJTlZBTElEX1NFU1NJT05fVE9LRU4iLCJkZWwiLCJnZXRTdWJzY3JpcHRpb25JbmZvIiwiYWNsR3JvdXAiLCJwdXNoIiwiU2NoZW1hQ29udHJvbGxlciIsInZhbGlkYXRlUGVybWlzc2lvbiIsImxlbmd0aCIsIm9iamVjdElkIiwiX3ZlcmlmeUFDTCIsInRva2VuIiwiaXNTdWJzY3JpcHRpb25TZXNzaW9uVG9rZW5NYXRjaGVkIiwiZ2V0UmVhZEFjY2VzcyIsImFjbF9oYXNfcm9sZXMiLCJwZXJtaXNzaW9uc0J5SWQiLCJzb21lIiwic3RhcnRzV2l0aCIsInJvbGVOYW1lcyIsImdldFVzZXJSb2xlcyIsInJvbGUiLCJnZXRTZXNzaW9uRnJvbUNsaWVudCIsImdldFB1YmxpY1JlYWRBY2Nlc3MiLCJzdWJzY3JpcHRpb25Ub2tlbiIsImNsaWVudFNlc3Npb25Ub2tlbiIsIl92YWxpZGF0ZUtleXMiLCJfaGFzTWFzdGVyS2V5IiwicmVxIiwicHVzaENvbm5lY3QiLCJ2YWxpZEtleVBhaXJzIiwicHJvdG90eXBlIiwiaGFzT3duUHJvcGVydHkiLCJjYWxsIiwiaXNWYWxpZCIsInNlY3JldCIsInBhcnNlUXVlcnkiLCJRdWVyeSIsIndpdGhKU09OIiwiZmllbGRzIiwic3BsaXQiLCJzdWJzY3JpcHRpb25IYXNoIiwiU3Vic2NyaXB0aW9uIiwid2hlcmUiLCJhZGRTdWJzY3JpcHRpb25JbmZvIiwiYWRkQ2xpZW50U3Vic2NyaXB0aW9uIiwicHVzaFN1YnNjcmliZSIsIm5vdGlmeUNsaWVudCIsImRlbGV0ZVN1YnNjcmlwdGlvbkluZm8iLCJwdXNoVW5zdWJzY3JpYmUiXSwibWFwcGluZ3Mi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QW1CMkgsTUFBbkIsQ0FBMEIvRSxTQUExQjtBQUNEOztBQUNELDZDQUEwQjtBQUN4QnFCLE1BQUFBLE1BRHdCO0FBRXhCWSxNQUFBQSxLQUFLLEVBQUUsYUFGaUI7QUFHeEIvRSxNQUFBQSxPQUFPLEVBQUUsS0FBS0EsT0FBTCxDQUFhc0QsSUFIRTtBQUl4QnBELE1BQUFBLGFBQWEsRUFBRSxLQUFLQSxhQUFMLENBQW1Cb0QsSUFKVjtBQUt4QjBCLE1BQUFBLFlBQVksRUFBRThDLGdCQUFnQixDQUFDOUMsWUFMUDtBQU14QkUsTUFBQUEsWUFBWSxFQUFFZixNQUFNLENBQUNnQixZQU5HO0FBT3hCQyxNQUFBQSxjQUFjLEVBQUVqQixNQUFNLENBQUNpQjtBQVBDLEtBQTFCOztBQVVBLFFBQUksQ0FBQ21HLFlBQUwsRUFBbUI7QUFDakI7QUFDRDs7QUFFRHBILElBQUFBLE1BQU0sQ0FBQ3NILGVBQVAsQ0FBdUJ0RSxPQUFPLENBQUM5QyxTQUEvQjs7QUFFQXpELG9CQUFPQyxPQUFQLENBQ0csa0JBQWlCYSxjQUFjLENBQUNvQyxRQUFTLG9CQUFtQnFELE9BQU8sQ0FBQzlDLFNBQVUsRUFEakY7QUFHRDs7QUF6MUJ3QiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB0djQgZnJvbSAndHY0JztcbmltcG9ydCBQYXJzZSBmcm9tICdwYXJzZS9ub2RlJztcbmltcG9ydCB7IFN1YnNjcmlwdGlvbiB9IGZyb20gJy4vU3Vic2NyaXB0aW9uJztcbmltcG9ydCB7IENsaWVudCB9IGZyb20gJy4vQ2xpZW50JztcbmltcG9ydCB7IFBhcnNlV2ViU29ja2V0U2VydmVyIH0gZnJvbSAnLi9QYXJzZVdlYlNvY2tldFNlcnZlcic7XG5pbXBvcnQgbG9nZ2VyIGZyb20gJy4uL2xvZ2dlcic7XG5pbXBvcnQgUmVxdWVzdFNjaGVtYSBmcm9tICcuL1JlcXVlc3RTY2hlbWEnO1xuaW1wb3J0IHsgbWF0Y2hlc1F1ZXJ5LCBxdWVyeUhhc2ggfSBmcm9tICcuL1F1ZXJ5VG9vbHMnO1xuaW1wb3J0IHsgUGFyc2VQdWJTdWIgfSBmcm9tICcuL1BhcnNlUHViU3ViJztcbmltcG9ydCBTY2hlbWFDb250cm9sbGVyIGZyb20gJy4uL0NvbnRyb2xsZXJzL1NjaGVtYUNvbnRyb2xsZXInO1xuaW1wb3J0IF8gZnJvbSAnbG9kYXNoJztcbmltcG9ydCB7IHY0IGFzIHV1aWR2NCB9IGZyb20gJ3V1aWQnO1xuaW1wb3J0IHsgcnVuTGl2ZVF1ZXJ5RXZlbnRIYW5kbGVycywgZ2V0VHJpZ2dlciwgcnVuVHJpZ2dlciB9IGZyb20gJy4uL3RyaWdnZXJzJztcbmltcG9ydCB7IGdldEF1dGhGb3JTZXNzaW9uVG9rZW4sIEF1dGggfSBmcm9tICcuLi9BdXRoJztcbmltcG9ydCB7IGdldENhY2hlQ29udHJvbGxlciB9IGZyb20gJy4uL0NvbnRyb2xsZXJzJztcbmltcG9ydCBMUlUgZnJvbSAnbHJ1LWNhY2hlJztcbmltcG9ydCBVc2VyUm91dGVyIGZyb20gJy4uL1JvdXRlcnMvVXNlcnNSb3V0ZXInO1xuXG5jbGFzcyBQYXJzZUxpdmVRdWVyeVNlcnZlciB7XG4gIGNsaWVudHM6IE1hcDtcbiAgLy8gY2xhc3NOYW1lIC0+IChxdWVyeUhhc2ggLT4gc3Vic2NyaXB0aW9uKVxuICBzdWJzY3JpcHRpb25zOiBPYmplY3Q7XG4gIHBhcnNlV2ViU29ja2V0U2VydmVyOiBPYmplY3Q7XG4gIGtleVBhaXJzOiBhbnk7XG4gIC8vIFRoZSBzdWJzY3JpYmVyIHdlIHVzZSB0byBnZXQgb2JqZWN0IHVwZGF0ZSBmcm9tIHB1Ymxpc2hlclxuICBzdWJzY3JpYmVyOiBPYmplY3Q7XG5cbiAgY29uc3RydWN0b3Ioc2VydmVyOiBhbnksIGNvbmZpZzogYW55ID0ge30sIHBhcnNlU2VydmVyQ29uZmlnOiBhbnkgPSB7fSkge1xuICAgIHRoaXMuc2VydmVyID0gc2VydmVyO1xuICAgIHRoaXMuY2xpZW50cyA9IG5ldyBNYXAoKTtcbiAgICB0aGlzLnN1YnNjcmlwdGlvbnMgPSBuZXcgTWFwKCk7XG4gICAgdGhpcy5jb25maWcgPSBjb25maWc7XG5cbiAgICBjb25maWcuYXBwSWQgPSBjb25maWcuYXBwSWQgfHwgUGFyc2UuYXBwbGljYXRpb25JZDtcbiAgICBjb25maWcubWFzdGVyS2V5ID0gY29uZmlnLm1hc3RlcktleSB8fCBQYXJzZS5tYXN0ZXJLZXk7XG5cbiAgICAvLyBTdG9yZSBrZXlzLCBjb252ZXJ0IG9iaiB0byBtYXBcbiAgICBjb25zdCBrZXlQYWlycyA9IGNvbmZpZy5rZXlQYWlycyB8fCB7fTtcbiAgICB0aGlzLmtleVBhaXJzID0gbmV3IE1hcCgpO1xuICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKGtleVBhaXJzKSkge1xuICAgICAgdGhpcy5rZXlQYWlycy5zZXQoa2V5LCBrZXlQYWlyc1trZXldKTtcbiAgICB9XG4gICAgbG9nZ2VyLnZlcmJvc2UoJ1N1cHBvcnQga2V5IHBhaXJzJywgdGhpcy5rZXlQYWlycyk7XG5cbiAgICAvLyBJbml0aWFsaXplIFBhcnNlXG4gICAgUGFyc2UuT2JqZWN0LmRpc2FibGVTaW5nbGVJbnN0YW5jZSgpO1xuICAgIGNvbnN0IHNlcnZlclVSTCA9IGNvbmZpZy5zZXJ2ZXJVUkwgfHwgUGFyc2Uuc2VydmVyVVJMO1xuICAgIFBhcnNlLnNlcnZlclVSTCA9IHNlcnZlclVSTDtcbiAgICBQYXJzZS5pbml0aWFsaXplKGNvbmZpZy5hcHBJZCwgUGFyc2UuamF2YVNjcmlwdEtleSwgY29uZmlnLm1hc3RlcktleSk7XG5cbiAgICAvLyBUaGUgY2FjaGUgY29udHJvbGxlciBpcyBhIHByb3BlciBjYWNoZSBjb250cm9sbGVyXG4gICAgLy8gd2l0aCBhY2Nlc3MgdG8gVXNlciBhbmQgUm9sZXNcbiAgICB0aGlzLmNhY2hlQ29udHJvbGxlciA9IGdldENhY2hlQ29udHJvbGxlcihwYXJzZVNlcnZlckNvbmZpZyk7XG5cbiAgICBjb25maWcuY2FjaGVUaW1lb3V0ID0gY29uZmlnLmNhY2hlVGltZW91dCB8fCA1ICogMTAwMDsgLy8gNXNcblxuICAgIC8vIFRoaXMgYXV0aCBjYWNoZSBzdG9yZXMgdGhlIHByb21pc2VzIGZvciBlYWNoIGF1dGggcmVzb2x1dGlvbi5cbiAgICAvLyBUaGUgbWFpbiBiZW5lZml0IGlzIHRvIGJlIGFibGUgdG8gcmV1c2UgdGhlIHNhbWUgdXNlciAvIHNlc3Npb24gdG9rZW4gcmVzb2x1dGlvbi5cbiAgICB0aGlzLmF1dGhDYWNoZSA9IG5ldyBMUlUoe1xuICAgICAgbWF4OiA1MDAsIC8vIDUwMCBjb25jdXJyZW50XG4gICAgICBtYXhBZ2U6IGNvbmZpZy5jYWNoZVRpbWVvdXQsXG4gICAgfSk7XG4gICAgLy8gSW5pdGlhbGl6ZSB3ZWJzb2NrZXQgc2VydmVyXG4gICAgdGhpcy5wYXJzZVdlYlNvY2tldFNlcnZlciA9IG5ldyBQYXJzZVdlYlNvY2tldFNlcnZlcihcbiAgICAgIHNlcnZlcixcbiAgICAgIHBhcnNlV2Vic29ja2V0ID0+IHRoaXMuX29uQ29ubmVjdChwYXJzZVdlYnNvY2tldCksXG4gICAgICBjb25maWdcbiAgICApO1xuXG4gICAgLy8gSW5pdGlhbGl6ZSBzdWJzY3JpYmVyXG4gICAgdGhpcy5zdWJzY3JpYmVyID0gUGFyc2VQdWJTdWIuY3JlYXRlU3Vic2NyaWJlcihjb25maWcpO1xuICAgIHRoaXMuc3Vic2NyaWJlci5zdWJzY3JpYmUoUGFyc2UuYXBwbGljYXRpb25JZCArICdhZnRlclNhdmUnKTtcbiAgICB0aGlzLnN1YnNjcmliZXIuc3Vic2NyaWJlKFBhcnNlLmFwcGxpY2F0aW9uSWQgKyAnYWZ0ZXJEZWxldGUnKTtcbiAgICAvLyBSZWdpc3RlciBtZXNzYWdlIGhhbmRsZXIgZm9yIHN1YnNjcmliZXIuIFdoZW4gcHVibGlzaGVyIGdldCBtZXNzYWdlcywgaXQgd2lsbCBwdWJsaXNoIG1lc3NhZ2VcbiAgICAvLyB0byB0aGUgc3Vic2NyaWJlcnMgYW5kIHRoZSBoYW5kbGVyIHdpbGwgYmUgY2FsbGVkLlxuICAgIHRoaXMuc3Vic2NyaWJlci5vbignbWVzc2FnZScsIChjaGFubmVsLCBtZXNzYWdlU3RyKSA9PiB7XG4gICAgICBsb2dnZXIudmVyYm9zZSgnU3Vic2NyaWJlIG1lc3NhZ2UgJWonLCBtZXNzYWdlU3RyKTtcbiAgICAgIGxldCBtZXNzYWdlO1xuICAgICAgdHJ5IHtcbiAgICAgICAgbWVzc2FnZSA9IEpTT04ucGFyc2UobWVzc2FnZVN0cik7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGxvZ2dlci5lcnJvcigndW5hYmxlIHRvIHBhcnNlIG1lc3NhZ2UnLCBtZXNzYWdlU3RyLCBlKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgdGhpcy5faW5mbGF0ZVBhcnNlT2JqZWN0KG1lc3NhZ2UpO1xuICAgICAgaWYgKGNoYW5uZWwgPT09IFBhcnNlLmFwcGxpY2F0aW9uSWQgKyAnYWZ0ZXJTYXZlJykge1xuICAgICAgICB0aGlzLl9vbkFmdGVyU2F2ZShtZXNzYWdlKTtcbiAgICAgIH0gZWxzZSBpZiAoY2hhbm5lbCA9PT0gUGFyc2UuYXBwbGljYXRpb25JZCArICdhZnRlckRlbGV0ZScpIHtcbiAgICAgICAgdGhpcy5fb25BZnRlckRlbGV0ZShtZXNzYWdlKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGxvZ2dlci5lcnJvcignR2V0IG1lc3NhZ2UgJXMgZnJvbSB1bmtub3duIGNoYW5uZWwgJWonLCBtZXNzYWdlLCBjaGFubmVsKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIC8vIE1lc3NhZ2UgaXMgdGhlIEpTT04gb2JqZWN0IGZyb20gcHVibGlzaGVyLiBNZXNzYWdlLmN1cnJlbnRQYXJzZU9iamVjdCBpcyB0aGUgUGFyc2VPYmplY3QgSlNPTiBhZnRlciBjaGFuZ2VzLlxuICAvLyBNZXNzYWdlLm9yaWdpbmFsUGFyc2VPYmplY3QgaXMgdGhlIG9yaWdpbmFsIFBhcnNlT2JqZWN0IEpTT04uXG4gIF9pbmZsYXRlUGFyc2VPYmplY3QobWVzc2FnZTogYW55KTogdm9pZCB7XG4gICAgLy8gSW5mbGF0ZSBtZXJnZWQgb2JqZWN0XG4gICAgY29uc3QgY3VycmVudFBhcnNlT2JqZWN0ID0gbWVzc2FnZS5jdXJyZW50UGFyc2VPYmplY3Q7XG4gICAgVXNlclJvdXRlci5yZW1vdmVIaWRkZW5Qcm9wZXJ0aWVzKGN1cnJlbnRQYXJzZU9iamVjdCk7XG4gICAgbGV0IGNsYXNzTmFtZSA9IGN1cnJlbnRQYXJzZU9iamVjdC5jbGFzc05hbWU7XG4gICAgbGV0IHBhcnNlT2JqZWN0ID0gbmV3IFBhcnNlLk9iamVjdChjbGFzc05hbWUpO1xuICAgIHBhcnNlT2JqZWN0Ll9maW5pc2hGZXRjaChjdXJyZW50UGFyc2VPYmplY3QpO1xuICAgIG1lc3NhZ2UuY3VycmVudFBhcnNlT2JqZWN0ID0gcGFyc2VPYmplY3Q7XG4gICAgLy8gSW5mbGF0ZSBvcmlnaW5hbCBvYmplY3RcbiAgICBjb25zdCBvcmlnaW5hbFBhcnNlT2JqZWN0ID0gbWVzc2FnZS5vcmlnaW5hbFBhcnNlT2JqZWN0O1xuICAgIGlmIChvcmlnaW5hbFBhcnNlT2JqZWN0KSB7XG4gICAgICBVc2VyUm91dGVyLnJlbW92ZUhpZGRlblByb3BlcnRpZXMob3JpZ2luYWxQYXJzZU9iamVjdCk7XG4gICAgICBjbGFzc05hbWUgPSBvcmlnaW5hbFBhcnNlT2JqZWN0LmNsYXNzTmFtZTtcbiAgICAgIHBhcnNlT2JqZWN0ID0gbmV3IFBhcnNlLk9iamVjdChjbGFzc05hbWUpO1xuICAgICAgcGFyc2VPYmplY3QuX2ZpbmlzaEZldGNoKG9yaWdpbmFsUGFyc2VPYmplY3QpO1xuICAgICAgbWVzc2FnZS5vcmlnaW5hbFBhcnNlT2JqZWN0ID0gcGFyc2VPYmplY3Q7XG4gICAgfVxuICB9XG5cbiAgLy8gTWVzc2FnZSBpcyB0aGUgSlNPTiBvYmplY3QgZnJvbSBwdWJsaXNoZXIgYWZ0ZXIgaW5mbGF0ZWQuIE1lc3NhZ2UuY3VycmVudFBhcnNlT2JqZWN0IGlzIHRoZSBQYXJzZU9iamVjdCBhZnRlciBjaGFuZ2VzLlxuICAvLyBNZXNzYWdlLm9yaWdpbmFsUGFyc2VPYmplY3QgaXMgdGhlIG9yaWdpbmFsIFBhcnNlT2JqZWN0LlxuICBhc3luYyBfb25BZnRlckRlbGV0ZShtZXNzYWdlOiBhbnkpOiB2b2lkIHtcbiAgICBsb2dnZXIudmVyYm9zZShQYXJzZS5hcHBsaWNhdGlvbklkICsgJ2FmdGVyRGVsZXRlIGlzIHRyaWdnZXJlZCcpO1xuXG4gICAgbGV0IGRlbGV0ZWRQYXJzZU9iamVjdCA9IG1lc3NhZ2UuY3VycmVudFBhcnNlT2JqZWN0LnRvSlNPTigpO1xuICAgIGNvbnN0IGNsYXNzTGV2ZWxQZXJtaXNzaW9ucyA9IG1lc3NhZ2UuY2xhc3NMZXZlbFBlcm1pc3Npb25zO1xuICAgIGNvbnN0IGNsYXNzTmFtZSA9IGRlbGV0ZWRQYXJzZU9iamVjdC5jbGFzc05hbWU7XG4gICAgbG9nZ2VyLnZlcmJvc2UoJ0NsYXNzTmFtZTogJWogfCBPYmplY3RJZDogJXMnLCBjbGFzc05hbWUsIGRlbGV0ZWRQYXJzZU9iamVjdC5pZCk7XG4gICAgbG9nZ2VyLnZlcmJvc2UoJ0N1cnJlbnQgY2xpZW50IG51bWJlciA6ICVkJywgdGhpcy5jbGllbnRzLnNpemUpO1xuXG4gICAgY29uc3QgY2xhc3NTdWJzY3JpcHRpb25zID0gdGhpcy5zdWJzY3JpcHRpb25zLmdldChjbGFzc05hbWUpO1xuICAgIGlmICh0eXBlb2YgY2xhc3NTdWJzY3JpcHRpb25zID09PSAndW5kZWZpbmVkJykge1xuICAgICAgbG9nZ2VyLmRlYnVnKCdDYW4gbm90IGZpbmQgc3Vic2NyaXB0aW9ucyB1bmRlciB0aGlzIGNsYXNzICcgKyBjbGFzc05hbWUpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGZvciAoY29uc3Qgc3Vic2NyaXB0aW9uIG9mIGNsYXNzU3Vic2NyaXB0aW9ucy52YWx1ZXMoKSkge1xuICAgICAgY29uc3QgaXNTdWJzY3JpcHRpb25NYXRjaGVkID0gdGhpcy5fbWF0Y2hlc1N1YnNjcmlwdGlvbihkZWxldGVkUGFyc2VPYmplY3QsIHN1YnNjcmlwdGlvbik7XG4gICAgICBpZiAoIWlzU3Vic2NyaXB0aW9uTWF0Y2hlZCkge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cbiAgICAgIGZvciAoY29uc3QgW2NsaWVudElkLCByZXF1ZXN0SWRzXSBvZiBfLmVudHJpZXMoc3Vic2NyaXB0aW9uLmNsaWVudFJlcXVlc3RJZHMpKSB7XG4gICAgICAgIGNvbnN0IGNsaWVudCA9IHRoaXMuY2xpZW50cy5nZXQoY2xpZW50SWQpO1xuICAgICAgICBpZiAodHlwZW9mIGNsaWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgfVxuICAgICAgICByZXF1ZXN0SWRzLmZvckVhY2goYXN5bmMgcmVxdWVzdElkID0+IHtcbiAgICAgICAgICBjb25zdCBhY2wgPSBtZXNzYWdlLmN1cnJlbnRQYXJzZU9iamVjdC5nZXRBQ0woKTtcbiAgICAgICAgICAvLyBDaGVjayBDTFBcbiAgICAgICAgICBjb25zdCBvcCA9IHRoaXMuX2dldENMUE9wZXJhdGlvbihzdWJzY3JpcHRpb24ucXVlcnkpO1xuICAgICAgICAgIGxldCByZXMgPSB7fTtcbiAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5fbWF0Y2hlc0NMUChcbiAgICAgICAgICAgICAgY2xhc3NMZXZlbFBlcm1pc3Npb25zLFxuICAgICAgICAgICAgICBtZXNzYWdlLmN1cnJlbnRQYXJzZU9iamVjdCxcbiAgICAgICAgICAgICAgY2xpZW50LFxuICAgICAgICAgICAgICByZXF1ZXN0SWQsXG4gICAgICAgICAgICAgIG9wXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgY29uc3QgaXNNYXRjaGVkID0gYXdhaXQgdGhpcy5fbWF0Y2hlc0FDTChhY2wsIGNsaWVudCwgcmVxdWVzdElkKTtcbiAgICAgICAgICAgIGlmICghaXNNYXRjaGVkKSB7XG4gICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmVzID0ge1xuICAgICAgICAgICAgICBldmVudDogJ2RlbGV0ZScsXG4gICAgICAgICAgICAgIHNlc3Npb25Ub2tlbjogY2xpZW50LnNlc3Npb25Ub2tlbixcbiAgICAgICAgICAgICAgb2JqZWN0OiBkZWxldGVkUGFyc2VPYmplY3QsXG4gICAgICAgICAgICAgIGNsaWVudHM6IHRoaXMuY2xpZW50cy5zaXplLFxuICAgICAgICAgICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICAgICAgICAgICAgdXNlTWFzdGVyS2V5OiBjbGllbnQuaGFzTWFzdGVyS2V5LFxuICAgICAgICAgICAgICBpbnN0YWxsYXRpb25JZDogY2xpZW50Lmluc3RhbGxhdGlvbklkLFxuICAgICAgICAgICAgICBzZW5kRXZlbnQ6IHRydWUsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgY29uc3QgdHJpZ2dlciA9IGdldFRyaWdnZXIoY2xhc3NOYW1lLCAnYWZ0ZXJFdmVudCcsIFBhcnNlLmFwcGxpY2F0aW9uSWQpO1xuICAgICAgICAgICAgaWYgKHRyaWdnZXIpIHtcbiAgICAgICAgICAgICAgY29uc3QgYXV0aCA9IGF3YWl0IHRoaXMuZ2V0QXV0aEZyb21DbGllbnQoY2xpZW50LCByZXF1ZXN0SWQpO1xuICAgICAgICAgICAgICBpZiAoYXV0aCAmJiBhdXRoLnVzZXIpIHtcbiAgICAgICAgICAgICAgICByZXMudXNlciA9IGF1dGgudXNlcjtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBpZiAocmVzLm9iamVjdCkge1xuICAgICAgICAgICAgICAgIHJlcy5vYmplY3QgPSBQYXJzZS5PYmplY3QuZnJvbUpTT04ocmVzLm9iamVjdCk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgYXdhaXQgcnVuVHJpZ2dlcih0cmlnZ2VyLCBgYWZ0ZXJFdmVudC4ke2NsYXNzTmFtZX1gLCByZXMsIGF1dGgpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKCFyZXMuc2VuZEV2ZW50KSB7XG4gICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChyZXMub2JqZWN0ICYmIHR5cGVvZiByZXMub2JqZWN0LnRvSlNPTiA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgICAgICBkZWxldGVkUGFyc2VPYmplY3QgPSByZXMub2JqZWN0LnRvSlNPTigpO1xuICAgICAgICAgICAgICBkZWxldGVkUGFyc2VPYmplY3QuY2xhc3NOYW1lID0gY2xhc3NOYW1lO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgY2xpZW50LnB1c2hEZWxldGUocmVxdWVzdElkLCBkZWxldGVkUGFyc2VPYmplY3QpO1xuICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICBDbGllbnQucHVzaEVycm9yKFxuICAgICAgICAgICAgICBjbGllbnQucGFyc2VXZWJTb2NrZXQsXG4gICAgICAgICAgICAgIGVycm9yLmNvZGUgfHwgMTQxLFxuICAgICAgICAgICAgICBlcnJvci5tZXNzYWdlIHx8IGVycm9yLFxuICAgICAgICAgICAgICBmYWxzZSxcbiAgICAgICAgICAgICAgcmVxdWVzdElkXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgbG9nZ2VyLmVycm9yKFxuICAgICAgICAgICAgICBgRmFpbGVkIHJ1bm5pbmcgYWZ0ZXJMaXZlUXVlcnlFdmVudCBvbiBjbGFzcyAke2NsYXNzTmFtZX0gZm9yIGV2ZW50ICR7cmVzLmV2ZW50fSB3aXRoIHNlc3Npb24gJHtyZXMuc2Vzc2lvblRva2VufSB3aXRoOlxcbiBFcnJvcjogYCArXG4gICAgICAgICAgICAgICAgSlNPTi5zdHJpbmdpZnkoZXJyb3IpXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgLy8gTWVzc2FnZSBpcyB0aGUgSlNPTiBvYmplY3QgZnJvbSBwdWJsaXNoZXIgYWZ0ZXIgaW5mbGF0ZWQuIE1lc3NhZ2UuY3VycmVudFBhcnNlT2JqZWN0IGlzIHRoZSBQYXJzZU9iamVjdCBhZnRlciBjaGFuZ2VzLlxuICAvLyBNZXNzYWdlLm9yaWdpbmFsUGFyc2VPYmplY3QgaXMgdGhlIG9yaWdpbmFsIFBhcnNlT2JqZWN0LlxuICBhc3luYyBfb25BZnRlclNhdmUobWVzc2FnZTogYW55KTogdm9pZCB7XG4gICAgbG9nZ2VyLnZlcmJvc2UoUGFyc2UuYXBwbGljYXRpb25JZCArICdhZnRlclNhdmUgaXMgdHJpZ2dlcmVkJyk7XG5cbiAgICBsZXQgb3JpZ2luYWxQYXJzZU9iamVjdCA9IG51bGw7XG4gICAgaWYgKG1lc3NhZ2Uub3JpZ2luYWxQYXJzZU9iamVjdCkge1xuICAgICAgb3JpZ2luYWxQYXJzZU9iamVjdCA9IG1lc3NhZ2Uub3JpZ2luYWxQYXJzZU9iamVjdC50b0pTT04oKTtcbiAgICB9XG4gICAgY29uc3QgY2xhc3NMZXZlbFBlcm1pc3Npb25zID0gbWVzc2FnZS5jbGFzc0xldmVsUGVybWlzc2lvbnM7XG4gICAgbGV0IGN1cnJlbnRQYXJzZU9iamVjdCA9IG1lc3NhZ2UuY3VycmVudFBhcnNlT2JqZWN0LnRvSlNPTigpO1xuICAgIGNvbnN0IGNsYXNzTmFtZSA9IGN1cnJlbnRQYXJzZU9iamVjdC5jbGFzc05hbWU7XG4gICAgbG9nZ2VyLnZlcmJvc2UoJ0NsYXNzTmFtZTogJXMgfCBPYmplY3RJZDogJXMnLCBjbGFzc05hbWUsIGN1cnJlbnRQYXJzZU9iamVjdC5pZCk7XG4gICAgbG9nZ2VyLnZlcmJvc2UoJ0N1cnJlbnQgY2xpZW50IG51bWJlciA6ICVkJywgdGhpcy5jbGllbnRzLnNpemUpO1xuXG4gICAgY29uc3QgY2xhc3NTdWJzY3JpcHRpb25zID0gdGhpcy5zdWJzY3JpcHRpb25zLmdldChjbGFzc05hbWUpO1xuICAgIGlmICh0eXBlb2YgY2xhc3NTdWJzY3JpcHRpb25zID09PSAndW5kZWZpbmVkJykge1xuICAgICAgbG9nZ2VyLmRlYnVnKCdDYW4gbm90IGZpbmQgc3Vic2NyaXB0aW9ucyB1bmRlciB0aGlzIGNsYXNzICcgKyBjbGFzc05hbWUpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBmb3IgKGNvbnN0IHN1YnNjcmlwdGlvbiBvZiBjbGFzc1N1YnNjcmlwdGlvbnMudmFsdWVzKCkpIHtcbiAgICAgIGNvbnN0IGlzT3JpZ2luYWxTdWJzY3JpcHRpb25NYXRjaGVkID0gdGhpcy5fbWF0Y2hlc1N1YnNjcmlwdGlvbihcbiAgICAgICAgb3JpZ2luYWxQYXJzZU9iamVjdCxcbiAgICAgICAgc3Vic2NyaXB0aW9uXG4gICAgICApO1xuICAgICAgY29uc3QgaXNDdXJyZW50U3Vic2NyaXB0aW9uTWF0Y2hlZCA9IHRoaXMuX21hdGNoZXNTdWJzY3JpcHRpb24oXG4gICAgICAgIGN1cnJlbnRQYXJzZU9iamVjdCxcbiAgICAgICAgc3Vic2NyaXB0aW9uXG4gICAgICApO1xuICAgICAgZm9yIChjb25zdCBbY2xpZW50SWQsIHJlcXVlc3RJZHNdIG9mIF8uZW50cmllcyhzdWJzY3JpcHRpb24uY2xpZW50UmVxdWVzdElkcykpIHtcbiAgICAgICAgY29uc3QgY2xpZW50ID0gdGhpcy5jbGllbnRzLmdldChjbGllbnRJZCk7XG4gICAgICAgIGlmICh0eXBlb2YgY2xpZW50ID09PSAndW5kZWZpbmVkJykge1xuICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICB9XG4gICAgICAgIHJlcXVlc3RJZHMuZm9yRWFjaChhc3luYyByZXF1ZXN0SWQgPT4ge1xuICAgICAgICAgIC8vIFNldCBvcmlnbmFsIFBhcnNlT2JqZWN0IEFDTCBjaGVja2luZyBwcm9taXNlLCBpZiB0aGUgb2JqZWN0IGRvZXMgbm90IG1hdGNoXG4gICAgICAgICAgLy8gc3Vic2NyaXB0aW9uLCB3ZSBkbyBub3QgbmVlZCB0byBjaGVjayBBQ0xcbiAgICAgICAgICBsZXQgb3JpZ2luYWxBQ0xDaGVja2luZ1Byb21pc2U7XG4gICAgICAgICAgaWYgKCFpc09yaWdpbmFsU3Vic2NyaXB0aW9uTWF0Y2hlZCkge1xuICAgICAgICAgICAgb3JpZ2luYWxBQ0xDaGVja2luZ1Byb21pc2UgPSBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBsZXQgb3JpZ2luYWxBQ0w7XG4gICAgICAgICAgICBpZiAobWVzc2FnZS5vcmlnaW5hbFBhcnNlT2JqZWN0KSB7XG4gICAgICAgICAgICAgIG9yaWdpbmFsQUNMID0gbWVzc2FnZS5vcmlnaW5hbFBhcnNlT2JqZWN0LmdldEFDTCgpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgb3JpZ2luYWxBQ0xDaGVja2luZ1Byb21pc2UgPSB0aGlzLl9tYXRjaGVzQUNMKG9yaWdpbmFsQUNMLCBjbGllbnQsIHJlcXVlc3RJZCk7XG4gICAgICAgICAgfVxuICAgICAgICAgIC8vIFNldCBjdXJyZW50IFBhcnNlT2JqZWN0IEFDTCBjaGVja2luZyBwcm9taXNlLCBpZiB0aGUgb2JqZWN0IGRvZXMgbm90IG1hdGNoXG4gICAgICAgICAgLy8gc3Vic2NyaXB0aW9uLCB3ZSBkbyBub3QgbmVlZCB0byBjaGVjayBBQ0xcbiAgICAgICAgICBsZXQgY3VycmVudEFDTENoZWNraW5nUHJvbWlzZTtcbiAgICAgICAgICBsZXQgcmVzID0ge307XG4gICAgICAgICAgaWYgKCFpc0N1cnJlbnRTdWJzY3JpcHRpb25NYXRjaGVkKSB7XG4gICAgICAgICAgICBjdXJyZW50QUNMQ2hlY2tpbmdQcm9taXNlID0gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgY29uc3QgY3VycmVudEFDTCA9IG1lc3NhZ2UuY3VycmVudFBhcnNlT2JqZWN0LmdldEFDTCgpO1xuICAgICAgICAgICAgY3VycmVudEFDTENoZWNraW5nUHJvbWlzZSA9IHRoaXMuX21hdGNoZXNBQ0woY3VycmVudEFDTCwgY2xpZW50LCByZXF1ZXN0SWQpO1xuICAgICAgICAgIH1cbiAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgY29uc3Qgb3AgPSB0aGlzLl9nZXRDTFBPcGVyYXRpb24oc3Vic2NyaXB0aW9uLnF1ZXJ5KTtcbiAgICAgICAgICAgIGF3YWl0IHRoaXMuX21hdGNoZXNDTFAoXG4gICAgICAgICAgICAgIGNsYXNzTGV2ZWxQZXJtaXNzaW9ucyxcbiAgICAgICAgICAgICAgbWVzc2FnZS5jdXJyZW50UGFyc2VPYmplY3QsXG4gICAgICAgICAgICAgIGNsaWVudCxcbiAgICAgICAgICAgICAgcmVxdWVzdElkLFxuICAgICAgICAgICAgICBvcFxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIGNvbnN0IFtpc09yaWdpbmFsTWF0Y2hlZCwgaXNDdXJyZW50TWF0Y2hlZF0gPSBhd2FpdCBQcm9taXNlLmFsbChbXG4gICAgICAgICAgICAgIG9yaWdpbmFsQUNMQ2hlY2tpbmdQcm9taXNlLFxuICAgICAgICAgICAgICBjdXJyZW50QUNMQ2hlY2tpbmdQcm9taXNlLFxuICAgICAgICAgICAgXSk7XG4gICAgICAgICAgICBsb2dnZXIudmVyYm9zZShcbiAgICAgICAgICAgICAgJ09yaWdpbmFsICVqIHwgQ3VycmVudCAlaiB8IE1hdGNoOiAlcywgJXMsICVzLCAlcyB8IFF1ZXJ5OiAlcycsXG4gICAgICAgICAgICAgIG9yaWdpbmFsUGFyc2VPYmplY3QsXG4gICAgICAgICAgICAgIGN1cnJlbnRQYXJzZU9iamVjdCxcbiAgICAgICAgICAgICAgaXNPcmlnaW5hbFN1YnNjcmlwdGlvbk1hdGNoZWQsXG4gICAgICAgICAgICAgIGlzQ3VycmVudFN1YnNjcmlwdGlvbk1hdGNoZWQsXG4gICAgICAgICAgICAgIGlzT3JpZ2luYWxNYXRjaGVkLFxuICAgICAgICAgICAgICBpc0N1cnJlbnRNYXRjaGVkLFxuICAgICAgICAgICAgICBzdWJzY3JpcHRpb24uaGFzaFxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIC8vIERlY2lkZSBldmVudCB0eXBlXG4gICAgICAgICAgICBsZXQgdHlwZTtcbiAgICAgICAgICAgIGlmIChpc09yaWdpbmFsTWF0Y2hlZCAmJiBpc0N1cnJlbnRNYXRjaGVkKSB7XG4gICAgICAgICAgICAgIHR5cGUgPSAndXBkYXRlJztcbiAgICAgICAgICAgIH0gZWxzZSBpZiAoaXNPcmlnaW5hbE1hdGNoZWQgJiYgIWlzQ3VycmVudE1hdGNoZWQpIHtcbiAgICAgICAgICAgICAgdHlwZSA9ICdsZWF2ZSc7XG4gICAgICAgICAgICB9IGVsc2UgaWYgKCFpc09yaWdpbmFsTWF0Y2hlZCAmJiBpc0N1cnJlbnRNYXRjaGVkKSB7XG4gICAgICAgICAgICAgIGlmIChvcmlnaW5hbFBhcnNlT2JqZWN0KSB7XG4gICAgICAgICAgICAgICAgdHlwZSA9ICdlbnRlcic7XG4gICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgdHlwZSA9ICdjcmVhdGUnO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJlcyA9IHtcbiAgICAgICAgICAgICAgZXZlbnQ6IHR5cGUsXG4gICAgICAgICAgICAgIHNlc3Npb25Ub2tlbjogY2xpZW50LnNlc3Npb25Ub2tlbixcbiAgICAgICAgICAgICAgb2JqZWN0OiBjdXJyZW50UGFyc2VPYmplY3QsXG4gICAgICAgICAgICAgIG9yaWdpbmFsOiBvcmlnaW5hbFBhcnNlT2JqZWN0LFxuICAgICAgICAgICAgICBjbGllbnRzOiB0aGlzLmNsaWVudHMuc2l6ZSxcbiAgICAgICAgICAgICAgc3Vic2NyaXB0aW9uczogdGhpcy5zdWJzY3JpcHRpb25zLnNpemUsXG4gICAgICAgICAgICAgIHVzZU1hc3RlcktleTogY2xpZW50Lmhhc01hc3RlcktleSxcbiAgICAgICAgICAgICAgaW5zdGFsbGF0aW9uSWQ6IGNsaWVudC5pbnN0YWxsYXRpb25JZCxcbiAgICAgICAgICAgICAgc2VuZEV2ZW50OiB0cnVlLFxuICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIGNvbnN0IHRyaWdnZXIgPSBnZXRUcmlnZ2VyKGNsYXNzTmFtZSwgJ2FmdGVyRXZlbnQnLCBQYXJzZS5hcHBsaWNhdGlvbklkKTtcbiAgICAgICAgICAgIGlmICh0cmlnZ2VyKSB7XG4gICAgICAgICAgICAgIGlmIChyZXMub2JqZWN0KSB7XG4gICAgICAgICAgICAgICAgcmVzLm9iamVjdCA9IFBhcnNlLk9iamVjdC5mcm9tSlNPTihyZXMub2JqZWN0KTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBpZiAocmVzLm9yaWdpbmFsKSB7XG4gICAgICAgICAgICAgICAgcmVzLm9yaWdpbmFsID0gUGFyc2UuT2JqZWN0LmZyb21KU09OKHJlcy5vcmlnaW5hbCk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgY29uc3QgYXV0aCA9IGF3YWl0IHRoaXMuZ2V0QXV0aEZyb21DbGllbnQoY2xpZW50LCByZXF1ZXN0SWQpO1xuICAgICAgICAgICAgICBpZiAoYXV0aCAmJiBhdXRoLnVzZXIpIHtcbiAgICAgICAgICAgICAgICByZXMudXNlciA9IGF1dGgudXNlcjtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBhd2FpdCBydW5UcmlnZ2VyKHRyaWdnZXIsIGBhZnRlckV2ZW50LiR7Y2xhc3NOYW1lfWAsIHJlcywgYXV0aCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoIXJlcy5zZW5kRXZlbnQpIHtcbiAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKHJlcy5vYmplY3QgJiYgdHlwZW9mIHJlcy5vYmplY3QudG9KU09OID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICAgIGN1cnJlbnRQYXJzZU9iamVjdCA9IHJlcy5vYmplY3QudG9KU09OKCk7XG4gICAgICAgICAgICAgIGN1cnJlbnRQYXJzZU9iamVjdC5jbGFzc05hbWUgPSByZXMub2JqZWN0LmNsYXNzTmFtZSB8fCBjbGFzc05hbWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmIChyZXMub3JpZ2luYWwgJiYgdHlwZW9mIHJlcy5vcmlnaW5hbC50b0pTT04gPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgICAgICAgb3JpZ2luYWxQYXJzZU9iamVjdCA9IHJlcy5vcmlnaW5hbC50b0pTT04oKTtcbiAgICAgICAgICAgICAgb3JpZ2luYWxQYXJzZU9iamVjdC5jbGFzc05hbWUgPSByZXMub3JpZ2luYWwuY2xhc3NOYW1lIHx8IGNsYXNzTmFtZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGNvbnN0IGZ1bmN0aW9uTmFtZSA9ICdwdXNoJyArIHJlcy5ldmVudC5jaGFyQXQoMCkudG9VcHBlckNhc2UoKSArIHJlcy5ldmVudC5zbGljZSgxKTtcbiAgICAgICAgICAgIGlmIChjbGllbnRbZnVuY3Rpb25OYW1lXSkge1xuICAgICAgICAgICAgICBjbGllbnRbZnVuY3Rpb25OYW1lXShyZXF1ZXN0SWQsIGN1cnJlbnRQYXJzZU9iamVjdCwgb3JpZ2luYWxQYXJzZU9iamVjdCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgIENsaWVudC5wdXNoRXJyb3IoXG4gICAgICAgICAgICAgIGNsaWVudC5wYXJzZVdlYlNvY2tldCxcbiAgICAgICAgICAgICAgZXJyb3IuY29kZSB8fCAxNDEsXG4gICAgICAgICAgICAgIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsXG4gICAgICAgICAgICAgIGZhbHNlLFxuICAgICAgICAgICAgICByZXF1ZXN0SWRcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICBsb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgIGBGYWlsZWQgcnVubmluZyBhZnRlckxpdmVRdWVyeUV2ZW50IG9uIGNsYXNzICR7Y2xhc3NOYW1lfSBmb3IgZXZlbnQgJHtyZXMuZXZlbnR9IHdpdGggc2Vzc2lvbiAke3Jlcy5zZXNzaW9uVG9rZW59IHdpdGg6XFxuIEVycm9yOiBgICtcbiAgICAgICAgICAgICAgICBKU09OLnN0cmluZ2lmeShlcnJvcilcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICBfb25Db25uZWN0KHBhcnNlV2Vic29ja2V0OiBhbnkpOiB2b2lkIHtcbiAgICBwYXJzZVdlYnNvY2tldC5vbignbWVzc2FnZScsIHJlcXVlc3QgPT4ge1xuICAgICAgaWYgKHR5cGVvZiByZXF1ZXN0ID09PSAnc3RyaW5nJykge1xuICAgICAgICB0cnkge1xuICAgICAgICAgIHJlcXVlc3QgPSBKU09OLnBhcnNlKHJlcXVlc3QpO1xuICAgICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgICAgbG9nZ2VyLmVycm9yKCd1bmFibGUgdG8gcGFyc2UgcmVxdWVzdCcsIHJlcXVlc3QsIGUpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgbG9nZ2VyLnZlcmJvc2UoJ1JlcXVlc3Q6ICVqJywgcmVxdWVzdCk7XG5cbiAgICAgIC8vIENoZWNrIHdoZXRoZXIgdGhpcyByZXF1ZXN0IGlzIGEgdmFsaWQgcmVxdWVzdCwgcmV0dXJuIGVycm9yIGRpcmVjdGx5IGlmIG5vdFxuICAgICAgaWYgKFxuICAgICAgICAhdHY0LnZhbGlkYXRlKHJlcXVlc3QsIFJlcXVlc3RTY2hlbWFbJ2dlbmVyYWwnXSkgfHxcbiAgICAgICAgIXR2NC52YWxpZGF0ZShyZXF1ZXN0LCBSZXF1ZXN0U2NoZW1hW3JlcXVlc3Qub3BdKVxuICAgICAgKSB7XG4gICAgICAgIENsaWVudC5wdXNoRXJyb3IocGFyc2VXZWJzb2NrZXQsIDEsIHR2NC5lcnJvci5tZXNzYWdlKTtcbiAgICAgICAgbG9nZ2VyLmVycm9yKCdDb25uZWN0IG1lc3NhZ2UgZXJyb3IgJXMnLCB0djQuZXJyb3IubWVzc2FnZSk7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgc3dpdGNoIChyZXF1ZXN0Lm9wKSB7XG4gICAgICAgIGNhc2UgJ2Nvbm5lY3QnOlxuICAgICAgICAgIHRoaXMuX2hhbmRsZUNvbm5lY3QocGFyc2VXZWJzb2NrZXQsIHJlcXVlc3QpO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICdzdWJzY3JpYmUnOlxuICAgICAgICAgIHRoaXMuX2hhbmRsZVN1YnNjcmliZShwYXJzZVdlYnNvY2tldCwgcmVxdWVzdCk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ3VwZGF0ZSc6XG4gICAgICAgICAgdGhpcy5faGFuZGxlVXBkYXRlU3Vic2NyaXB0aW9uKHBhcnNlV2Vic29ja2V0LCByZXF1ZXN0KTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAndW5zdWJzY3JpYmUnOlxuICAgICAgICAgIHRoaXMuX2hhbmRsZVVuc3Vic2NyaWJlKHBhcnNlV2Vic29ja2V0LCByZXF1ZXN0KTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICBDbGllbnQucHVzaEVycm9yKHBhcnNlV2Vic29ja2V0LCAzLCAnR2V0IHVua25vd24gb3BlcmF0aW9uJyk7XG4gICAgICAgICAgbG9nZ2VyLmVycm9yKCdHZXQgdW5rbm93biBvcGVyYXRpb24nLCByZXF1ZXN0Lm9wKTtcbiAgICAgIH1cbiAgICB9KTtcblxuICAgIHBhcnNlV2Vic29ja2V0Lm9uKCdkaXNjb25uZWN0JywgKCkgPT4ge1xuICAgICAgbG9nZ2VyLmluZm8oYENsaWVudCBkaXNjb25uZWN0OiAke3BhcnNlV2Vic29ja2V0LmNsaWVudElkfWApO1xuICAgICAgY29uc3QgY2xpZW50SWQgPSBwYXJzZVdlYnNvY2tldC5jbGllbnRJZDtcbiAgICAgIGlmICghdGhpcy5jbGllbnRzLmhhcyhjbGllbnRJZCkpIHtcbiAgICAgICAgcnVuTGl2ZVF1ZXJ5RXZlbnRIYW5kbGVycyh7XG4gICAgICAgICAgZXZlbnQ6ICd3c19kaXNjb25uZWN0X2Vycm9yJyxcbiAgICAgICAgICBjbGllbnRzOiB0aGlzLmNsaWVudHMuc2l6ZSxcbiAgICAgICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICAgICAgICBlcnJvcjogYFVuYWJsZSB0byBmaW5kIGNsaWVudCAke2NsaWVudElkfWAsXG4gICAgICAgIH0pO1xuICAgICAgICBsb2dnZXIuZXJyb3IoYENhbiBub3QgZmluZCBjbGllbnQgJHtjbGllbnRJZH0gb24gZGlzY29ubmVjdGApO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIC8vIERlbGV0ZSBjbGllbnRcbiAgICAgIGNvbnN0IGNsaWVudCA9IHRoaXMuY2xpZW50cy5nZXQoY2xpZW50SWQpO1xuICAgICAgdGhpcy5jbGllbnRzLmRlbGV0ZShjbGllbnRJZCk7XG5cbiAgICAgIC8vIERlbGV0ZSBjbGllbnQgZnJvbSBzdWJzY3JpcHRpb25zXG4gICAgICBmb3IgKGNvbnN0IFtyZXF1ZXN0SWQsIHN1YnNjcmlwdGlvbkluZm9dIG9mIF8uZW50cmllcyhjbGllbnQuc3Vic2NyaXB0aW9uSW5mb3MpKSB7XG4gICAgICAgIGNvbnN0IHN1YnNjcmlwdGlvbiA9IHN1YnNjcmlwdGlvbkluZm8uc3Vic2NyaXB0aW9uO1xuICAgICAgICBzdWJzY3JpcHRpb24uZGVsZXRlQ2xpZW50U3Vic2NyaXB0aW9uKGNsaWVudElkLCByZXF1ZXN0SWQpO1xuXG4gICAgICAgIC8vIElmIHRoZXJlIGlzIG5vIGNsaWVudCB3aGljaCBpcyBzdWJzY3JpYmluZyB0aGlzIHN1YnNjcmlwdGlvbiwgcmVtb3ZlIGl0IGZyb20gc3Vic2NyaXB0aW9uc1xuICAgICAgICBjb25zdCBjbGFzc1N1YnNjcmlwdGlvbnMgPSB0aGlzLnN1YnNjcmlwdGlvbnMuZ2V0KHN1YnNjcmlwdGlvbi5jbGFzc05hbWUpO1xuICAgICAgICBpZiAoIXN1YnNjcmlwdGlvbi5oYXNTdWJzY3JpYmluZ0NsaWVudCgpKSB7XG4gICAgICAgICAgY2xhc3NTdWJzY3JpcHRpb25zLmRlbGV0ZShzdWJzY3JpcHRpb24uaGFzaCk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gSWYgdGhlcmUgaXMgbm8gc3Vic2NyaXB0aW9ucyB1bmRlciB0aGlzIGNsYXNzLCByZW1vdmUgaXQgZnJvbSBzdWJzY3JpcHRpb25zXG4gICAgICAgIGlmIChjbGFzc1N1YnNjcmlwdGlvbnMuc2l6ZSA9PT0gMCkge1xuICAgICAgICAgIHRoaXMuc3Vic2NyaXB0aW9ucy5kZWxldGUoc3Vic2NyaXB0aW9uLmNsYXNzTmFtZSk7XG4gICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgbG9nZ2VyLnZlcmJvc2UoJ0N1cnJlbnQgY2xpZW50cyAlZCcsIHRoaXMuY2xpZW50cy5zaXplKTtcbiAgICAgIGxvZ2dlci52ZXJib3NlKCdDdXJyZW50IHN1YnNjcmlwdGlvbnMgJWQnLCB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSk7XG4gICAgICBydW5MaXZlUXVlcnlFdmVudEhhbmRsZXJzKHtcbiAgICAgICAgZXZlbnQ6ICd3c19kaXNjb25uZWN0JyxcbiAgICAgICAgY2xpZW50czogdGhpcy5jbGllbnRzLnNpemUsXG4gICAgICAgIHN1YnNjcmlwdGlvbnM6IHRoaXMuc3Vic2NyaXB0aW9ucy5zaXplLFxuICAgICAgICB1c2VNYXN0ZXJLZXk6IGNsaWVudC5oYXNNYXN0ZXJLZXksXG4gICAgICAgIGluc3RhbGxhdGlvbklkOiBjbGllbnQuaW5zdGFsbGF0aW9uSWQsXG4gICAgICAgIHNlc3Npb25Ub2tlbjogY2xpZW50LnNlc3Npb25Ub2tlbixcbiAgICAgIH0pO1xuICAgIH0pO1xuXG4gICAgcnVuTGl2ZVF1ZXJ5RXZlbnRIYW5kbGVycyh7XG4gICAgICBldmVudDogJ3dzX2Nvbm5lY3QnLFxuICAgICAgY2xpZW50czogdGhpcy5jbGllbnRzLnNpemUsXG4gICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICB9KTtcbiAgfVxuXG4gIF9tYXRjaGVzU3Vic2NyaXB0aW9uKHBhcnNlT2JqZWN0OiBhbnksIHN1YnNjcmlwdGlvbjogYW55KTogYm9vbGVhbiB7XG4gICAgLy8gT2JqZWN0IGlzIHVuZGVmaW5lZCBvciBudWxsLCBub3QgbWF0Y2hcbiAgICBpZiAoIXBhcnNlT2JqZWN0KSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIHJldHVybiBtYXRjaGVzUXVlcnkocGFyc2VPYmplY3QsIHN1YnNjcmlwdGlvbi5xdWVyeSk7XG4gIH1cblxuICBnZXRBdXRoRm9yU2Vzc2lvblRva2VuKHNlc3Npb25Ub2tlbjogP3N0cmluZyk6IFByb21pc2U8eyBhdXRoOiA/QXV0aCwgdXNlcklkOiA/c3RyaW5nIH0+IHtcbiAgICBpZiAoIXNlc3Npb25Ub2tlbikge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh7fSk7XG4gICAgfVxuICAgIGNvbnN0IGZyb21DYWNoZSA9IHRoaXMuYXV0aENhY2hlLmdldChzZXNzaW9uVG9rZW4pO1xuICAgIGlmIChmcm9tQ2FjaGUpIHtcbiAgICAgIHJldHVybiBmcm9tQ2FjaGU7XG4gICAgfVxuICAgIGNvbnN0IGF1dGhQcm9taXNlID0gZ2V0QXV0aEZvclNlc3Npb25Ub2tlbih7XG4gICAgICBjYWNoZUNvbnRyb2xsZXI6IHRoaXMuY2FjaGVDb250cm9sbGVyLFxuICAgICAgc2Vzc2lvblRva2VuOiBzZXNzaW9uVG9rZW4sXG4gICAgfSlcbiAgICAgIC50aGVuKGF1dGggPT4ge1xuICAgICAgICByZXR1cm4geyBhdXRoLCB1c2VySWQ6IGF1dGggJiYgYXV0aC51c2VyICYmIGF1dGgudXNlci5pZCB9O1xuICAgICAgfSlcbiAgICAgIC5jYXRjaChlcnJvciA9PiB7XG4gICAgICAgIC8vIFRoZXJlIHdhcyBhbiBlcnJvciB3aXRoIHRoZSBzZXNzaW9uIHRva2VuXG4gICAgICAgIGNvbnN0IHJlc3VsdCA9IHt9O1xuICAgICAgICBpZiAoZXJyb3IgJiYgZXJyb3IuY29kZSA9PT0gUGFyc2UuRXJyb3IuSU5WQUxJRF9TRVNTSU9OX1RPS0VOKSB7XG4gICAgICAgICAgcmVzdWx0LmVycm9yID0gZXJyb3I7XG4gICAgICAgICAgdGhpcy5hdXRoQ2FjaGUuc2V0KHNlc3Npb25Ub2tlbiwgUHJvbWlzZS5yZXNvbHZlKHJlc3VsdCksIHRoaXMuY29uZmlnLmNhY2hlVGltZW91dCk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdGhpcy5hdXRoQ2FjaGUuZGVsKHNlc3Npb25Ub2tlbik7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICAgIH0pO1xuICAgIHRoaXMuYXV0aENhY2hlLnNldChzZXNzaW9uVG9rZW4sIGF1dGhQcm9taXNlKTtcbiAgICByZXR1cm4gYXV0aFByb21pc2U7XG4gIH1cblxuICBhc3luYyBfbWF0Y2hlc0NMUChcbiAgICBjbGFzc0xldmVsUGVybWlzc2lvbnM6ID9hbnksXG4gICAgb2JqZWN0OiBhbnksXG4gICAgY2xpZW50OiBhbnksXG4gICAgcmVxdWVzdElkOiBudW1iZXIsXG4gICAgb3A6IHN0cmluZ1xuICApOiBhbnkge1xuICAgIC8vIHRyeSB0byBtYXRjaCBvbiB1c2VyIGZpcnN0LCBsZXNzIGV4cGVuc2l2ZSB0aGFuIHdpdGggcm9sZXNcbiAgICBjb25zdCBzdWJzY3JpcHRpb25JbmZvID0gY2xpZW50LmdldFN1YnNjcmlwdGlvbkluZm8ocmVxdWVzdElkKTtcbiAgICBjb25zdCBhY2xHcm91cCA9IFsnKiddO1xuICAgIGxldCB1c2VySWQ7XG4gICAgaWYgKHR5cGVvZiBzdWJzY3JpcHRpb25JbmZvICE9PSAndW5kZWZpbmVkJykge1xuICAgICAgY29uc3QgeyB1c2VySWQgfSA9IGF3YWl0IHRoaXMuZ2V0QXV0aEZvclNlc3Npb25Ub2tlbihzdWJzY3JpcHRpb25JbmZvLnNlc3Npb25Ub2tlbik7XG4gICAgICBpZiAodXNlcklkKSB7XG4gICAgICAgIGFjbEdyb3VwLnB1c2godXNlcklkKTtcbiAgICAgIH1cbiAgICB9XG4gICAgdHJ5IHtcbiAgICAgIGF3YWl0IFNjaGVtYUNvbnRyb2xsZXIudmFsaWRhdGVQZXJtaXNzaW9uKFxuICAgICAgICBjbGFzc0xldmVsUGVybWlzc2lvbnMsXG4gICAgICAgIG9iamVjdC5jbGFzc05hbWUsXG4gICAgICAgIGFjbEdyb3VwLFxuICAgICAgICBvcFxuICAgICAgKTtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgIGxvZ2dlci52ZXJib3NlKGBGYWlsZWQgbWF0Y2hpbmcgQ0xQIGZvciAke29iamVjdC5pZH0gJHt1c2VySWR9ICR7ZX1gKTtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgLy8gVE9ETzogaGFuZGxlIHJvbGVzIHBlcm1pc3Npb25zXG4gICAgLy8gT2JqZWN0LmtleXMoY2xhc3NMZXZlbFBlcm1pc3Npb25zKS5mb3JFYWNoKChrZXkpID0+IHtcbiAgICAvLyAgIGNvbnN0IHBlcm0gPSBjbGFzc0xldmVsUGVybWlzc2lvbnNba2V5XTtcbiAgICAvLyAgIE9iamVjdC5rZXlzKHBlcm0pLmZvckVhY2goKGtleSkgPT4ge1xuICAgIC8vICAgICBpZiAoa2V5LmluZGV4T2YoJ3JvbGUnKSlcbiAgICAvLyAgIH0pO1xuICAgIC8vIH0pXG4gICAgLy8gLy8gaXQncyByZWplY3RlZCBoZXJlLCBjaGVjayB0aGUgcm9sZXNcbiAgICAvLyB2YXIgcm9sZXNRdWVyeSA9IG5ldyBQYXJzZS5RdWVyeShQYXJzZS5Sb2xlKTtcbiAgICAvLyByb2xlc1F1ZXJ5LmVxdWFsVG8oXCJ1c2Vyc1wiLCB1c2VyKTtcbiAgICAvLyByZXR1cm4gcm9sZXNRdWVyeS5maW5kKHt1c2VNYXN0ZXJLZXk6dHJ1ZX0pO1xuICB9XG5cbiAgX2dldENMUE9wZXJhdGlvbihxdWVyeTogYW55KSB7XG4gICAgcmV0dXJuIHR5cGVvZiBxdWVyeSA9PT0gJ29iamVjdCcgJiZcbiAgICAgIE9iamVjdC5rZXlzKHF1ZXJ5KS5sZW5ndGggPT0gMSAmJlxuICAgICAgdHlwZW9mIHF1ZXJ5Lm9iamVjdElkID09PSAnc3RyaW5nJ1xuICAgICAgPyAnZ2V0J1xuICAgICAgOiAnZmluZCc7XG4gIH1cblxuICBhc3luYyBfdmVyaWZ5QUNMKGFjbDogYW55LCB0b2tlbjogc3RyaW5nKSB7XG4gICAgaWYgKCF0b2tlbikge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIGNvbnN0IHsgYXV0aCwgdXNlcklkIH0gPSBhd2FpdCB0aGlzLmdldEF1dGhGb3JTZXNzaW9uVG9rZW4odG9rZW4pO1xuXG4gICAgLy8gR2V0dGluZyB0aGUgc2Vzc2lvbiB0b2tlbiBmYWlsZWRcbiAgICAvLyBUaGlzIG1lYW5zIHRoYXQgbm8gYWRkaXRpb25hbCBhdXRoIGlzIGF2YWlsYWJsZVxuICAgIC8vIEF0IHRoaXMgcG9pbnQsIGp1c3QgYmFpbCBvdXQgYXMgbm8gYWRkaXRpb25hbCB2aXNpYmlsaXR5IGNhbiBiZSBpbmZlcnJlZC5cbiAgICBpZiAoIWF1dGggfHwgIXVzZXJJZCkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgICBjb25zdCBpc1N1YnNjcmlwdGlvblNlc3Npb25Ub2tlbk1hdGNoZWQgPSBhY2wuZ2V0UmVhZEFjY2Vzcyh1c2VySWQpO1xuICAgIGlmIChpc1N1YnNjcmlwdGlvblNlc3Npb25Ub2tlbk1hdGNoZWQpIHtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIC8vIENoZWNrIGlmIHRoZSB1c2VyIGhhcyBhbnkgcm9sZXMgdGhhdCBtYXRjaCB0aGUgQUNMXG4gICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpXG4gICAgICAudGhlbihhc3luYyAoKSA9PiB7XG4gICAgICAgIC8vIFJlc29sdmUgZmFsc2UgcmlnaHQgYXdheSBpZiB0aGUgYWNsIGRvZXNuJ3QgaGF2ZSBhbnkgcm9sZXNcbiAgICAgICAgY29uc3QgYWNsX2hhc19yb2xlcyA9IE9iamVjdC5rZXlzKGFjbC5wZXJtaXNzaW9uc0J5SWQpLnNvbWUoa2V5ID0+IGtleS5zdGFydHNXaXRoKCdyb2xlOicpKTtcbiAgICAgICAgaWYgKCFhY2xfaGFzX3JvbGVzKSB7XG4gICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3Qgcm9sZU5hbWVzID0gYXdhaXQgYXV0aC5nZXRVc2VyUm9sZXMoKTtcbiAgICAgICAgLy8gRmluYWxseSwgc2VlIGlmIGFueSBvZiB0aGUgdXNlcidzIHJvbGVzIGFsbG93IHRoZW0gcmVhZCBhY2Nlc3NcbiAgICAgICAgZm9yIChjb25zdCByb2xlIG9mIHJvbGVOYW1lcykge1xuICAgICAgICAgIC8vIFdlIHVzZSBnZXRSZWFkQWNjZXNzIGFzIGByb2xlYCBpcyBpbiB0aGUgZm9ybSBgcm9sZTpyb2xlTmFtZWBcbiAgICAgICAgICBpZiAoYWNsLmdldFJlYWRBY2Nlc3Mocm9sZSkpIHtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9KVxuICAgICAgLmNhdGNoKCgpID0+IHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfSk7XG4gIH1cblxuICBhc3luYyBnZXRBdXRoRnJvbUNsaWVudChjbGllbnQ6IGFueSwgcmVxdWVzdElkOiBudW1iZXIsIHNlc3Npb25Ub2tlbjogc3RyaW5nKSB7XG4gICAgY29uc3QgZ2V0U2Vzc2lvbkZyb21DbGllbnQgPSAoKSA9PiB7XG4gICAgICBjb25zdCBzdWJzY3JpcHRpb25JbmZvID0gY2xpZW50LmdldFN1YnNjcmlwdGlvbkluZm8ocmVxdWVzdElkKTtcbiAgICAgIGlmICh0eXBlb2Ygc3Vic2NyaXB0aW9uSW5mbyA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgcmV0dXJuIGNsaWVudC5zZXNzaW9uVG9rZW47XG4gICAgICB9XG4gICAgICByZXR1cm4gc3Vic2NyaXB0aW9uSW5mby5zZXNzaW9uVG9rZW4gfHwgY2xpZW50LnNlc3Npb25Ub2tlbjtcbiAgICB9O1xuICAgIGlmICghc2Vzc2lvblRva2VuKSB7XG4gICAgICBzZXNzaW9uVG9rZW4gPSBnZXRTZXNzaW9uRnJvbUNsaWVudCgpO1xuICAgIH1cbiAgICBpZiAoIXNlc3Npb25Ub2tlbikge1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBjb25zdCB7IGF1dGggfSA9IGF3YWl0IHRoaXMuZ2V0QXV0aEZvclNlc3Npb25Ub2tlbihzZXNzaW9uVG9rZW4pO1xuICAgIHJldHVybiBhdXRoO1xuICB9XG5cbiAgYXN5bmMgX21hdGNoZXNBQ0woYWNsOiBhbnksIGNsaWVudDogYW55LCByZXF1ZXN0SWQ6IG51bWJlcik6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIC8vIFJldHVybiB0cnVlIGRpcmVjdGx5IGlmIEFDTCBpc24ndCBwcmVzZW50LCBBQ0wgaXMgcHVibGljIHJlYWQsIG9yIGNsaWVudCBoYXMgbWFzdGVyIGtleVxuICAgIGlmICghYWNsIHx8IGFjbC5nZXRQdWJsaWNSZWFkQWNjZXNzKCkgfHwgY2xpZW50Lmhhc01hc3RlcktleSkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIC8vIENoZWNrIHN1YnNjcmlwdGlvbiBzZXNzaW9uVG9rZW4gbWF0Y2hlcyBBQ0wgZmlyc3RcbiAgICBjb25zdCBzdWJzY3JpcHRpb25JbmZvID0gY2xpZW50LmdldFN1YnNjcmlwdGlvbkluZm8ocmVxdWVzdElkKTtcbiAgICBpZiAodHlwZW9mIHN1YnNjcmlwdGlvbkluZm8gPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgY29uc3Qgc3Vic2NyaXB0aW9uVG9rZW4gPSBzdWJzY3JpcHRpb25JbmZvLnNlc3Npb25Ub2tlbjtcbiAgICBjb25zdCBjbGllbnRTZXNzaW9uVG9rZW4gPSBjbGllbnQuc2Vzc2lvblRva2VuO1xuXG4gICAgaWYgKGF3YWl0IHRoaXMuX3ZlcmlmeUFDTChhY2wsIHN1YnNjcmlwdGlvblRva2VuKSkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgaWYgKGF3YWl0IHRoaXMuX3ZlcmlmeUFDTChhY2wsIGNsaWVudFNlc3Npb25Ub2tlbikpIHtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIGFzeW5jIF9oYW5kbGVDb25uZWN0KHBhcnNlV2Vic29ja2V0OiBhbnksIHJlcXVlc3Q6IGFueSk6IGFueSB7XG4gICAgaWYgKCF0aGlzLl92YWxpZGF0ZUtleXMocmVxdWVzdCwgdGhpcy5rZXlQYWlycykpIHtcbiAgICAgIENsaWVudC5wdXNoRXJyb3IocGFyc2VXZWJzb2NrZXQsIDQsICdLZXkgaW4gcmVxdWVzdCBpcyBub3QgdmFsaWQnKTtcbiAgICAgIGxvZ2dlci5lcnJvcignS2V5IGluIHJlcXVlc3QgaXMgbm90IHZhbGlkJyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGNvbnN0IGhhc01hc3RlcktleSA9IHRoaXMuX2hhc01hc3RlcktleShyZXF1ZXN0LCB0aGlzLmtleVBhaXJzKTtcbiAgICBjb25zdCBjbGllbnRJZCA9IHV1aWR2NCgpO1xuICAgIGNvbnN0IGNsaWVudCA9IG5ldyBDbGllbnQoXG4gICAgICBjbGllbnRJZCxcbiAgICAgIHBhcnNlV2Vic29ja2V0LFxuICAgICAgaGFzTWFzdGVyS2V5LFxuICAgICAgcmVxdWVzdC5zZXNzaW9uVG9rZW4sXG4gICAgICByZXF1ZXN0Lmluc3RhbGxhdGlvbklkXG4gICAgKTtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcmVxID0ge1xuICAgICAgICBjbGllbnQsXG4gICAgICAgIGV2ZW50OiAnY29ubmVjdCcsXG4gICAgICAgIGNsaWVudHM6IHRoaXMuY2xpZW50cy5zaXplLFxuICAgICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICAgICAgc2Vzc2lvblRva2VuOiByZXF1ZXN0LnNlc3Npb25Ub2tlbixcbiAgICAgICAgdXNlTWFzdGVyS2V5OiBjbGllbnQuaGFzTWFzdGVyS2V5LFxuICAgICAgICBpbnN0YWxsYXRpb25JZDogcmVxdWVzdC5pbnN0YWxsYXRpb25JZCxcbiAgICAgIH07XG4gICAgICBjb25zdCB0cmlnZ2VyID0gZ2V0VHJpZ2dlcignQENvbm5lY3QnLCAnYmVmb3JlQ29ubmVjdCcsIFBhcnNlLmFwcGxpY2F0aW9uSWQpO1xuICAgICAgaWYgKHRyaWdnZXIpIHtcbiAgICAgICAgY29uc3QgYXV0aCA9IGF3YWl0IHRoaXMuZ2V0QXV0aEZyb21DbGllbnQoY2xpZW50LCByZXF1ZXN0LnJlcXVlc3RJZCwgcmVxLnNlc3Npb25Ub2tlbik7XG4gICAgICAgIGlmIChhdXRoICYmIGF1dGgudXNlcikge1xuICAgICAgICAgIHJlcS51c2VyID0gYXV0aC51c2VyO1xuICAgICAgICB9XG4gICAgICAgIGF3YWl0IHJ1blRyaWdnZXIodHJpZ2dlciwgYGJlZm9yZUNvbm5lY3QuQENvbm5lY3RgLCByZXEsIGF1dGgpO1xuICAgICAgfVxuICAgICAgcGFyc2VXZWJzb2NrZXQuY2xpZW50SWQgPSBjbGllbnRJZDtcbiAgICAgIHRoaXMuY2xpZW50cy5zZXQocGFyc2VXZWJzb2NrZXQuY2xpZW50SWQsIGNsaWVudCk7XG4gICAgICBsb2dnZXIuaW5mbyhgQ3JlYXRlIG5ldyBjbGllbnQ6ICR7cGFyc2VXZWJzb2NrZXQuY2xpZW50SWR9YCk7XG4gICAgICBjbGllbnQucHVzaENvbm5lY3QoKTtcbiAgICAgIHJ1bkxpdmVRdWVyeUV2ZW50SGFuZGxlcnMocmVxKTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgQ2xpZW50LnB1c2hFcnJvcihwYXJzZVdlYnNvY2tldCwgZXJyb3IuY29kZSB8fCAxNDEsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIGZhbHNlKTtcbiAgICAgIGxvZ2dlci5lcnJvcihcbiAgICAgICAgYEZhaWxlZCBydW5uaW5nIGJlZm9yZUNvbm5lY3QgZm9yIHNlc3Npb24gJHtyZXF1ZXN0LnNlc3Npb25Ub2tlbn0gd2l0aDpcXG4gRXJyb3I6IGAgK1xuICAgICAgICAgIEpTT04uc3RyaW5naWZ5KGVycm9yKVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICBfaGFzTWFzdGVyS2V5KHJlcXVlc3Q6IGFueSwgdmFsaWRLZXlQYWlyczogYW55KTogYm9vbGVhbiB7XG4gICAgaWYgKCF2YWxpZEtleVBhaXJzIHx8IHZhbGlkS2V5UGFpcnMuc2l6ZSA9PSAwIHx8ICF2YWxpZEtleVBhaXJzLmhhcygnbWFzdGVyS2V5JykpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgaWYgKCFyZXF1ZXN0IHx8ICFPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocmVxdWVzdCwgJ21hc3RlcktleScpKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIHJldHVybiByZXF1ZXN0Lm1hc3RlcktleSA9PT0gdmFsaWRLZXlQYWlycy5nZXQoJ21hc3RlcktleScpO1xuICB9XG5cbiAgX3ZhbGlkYXRlS2V5cyhyZXF1ZXN0OiBhbnksIHZhbGlkS2V5UGFpcnM6IGFueSk6IGJvb2xlYW4ge1xuICAgIGlmICghdmFsaWRLZXlQYWlycyB8fCB2YWxpZEtleVBhaXJzLnNpemUgPT0gMCkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGxldCBpc1ZhbGlkID0gZmFsc2U7XG4gICAgZm9yIChjb25zdCBba2V5LCBzZWNyZXRdIG9mIHZhbGlkS2V5UGFpcnMpIHtcbiAgICAgIGlmICghcmVxdWVzdFtrZXldIHx8IHJlcXVlc3Rba2V5XSAhPT0gc2VjcmV0KSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgaXNWYWxpZCA9IHRydWU7XG4gICAgICBicmVhaztcbiAgICB9XG4gICAgcmV0dXJuIGlzVmFsaWQ7XG4gIH1cblxuICBhc3luYyBfaGFuZGxlU3Vic2NyaWJlKHBhcnNlV2Vic29ja2V0OiBhbnksIHJlcXVlc3Q6IGFueSk6IGFueSB7XG4gICAgLy8gSWYgd2UgY2FuIG5vdCBmaW5kIHRoaXMgY2xpZW50LCByZXR1cm4gZXJyb3IgdG8gY2xpZW50XG4gICAgaWYgKCFPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocGFyc2VXZWJzb2NrZXQsICdjbGllbnRJZCcpKSB7XG4gICAgICBDbGllbnQucHVzaEVycm9yKFxuICAgICAgICBwYXJzZVdlYnNvY2tldCxcbiAgICAgICAgMixcbiAgICAgICAgJ0NhbiBub3QgZmluZCB0aGlzIGNsaWVudCwgbWFrZSBzdXJlIHlvdSBjb25uZWN0IHRvIHNlcnZlciBiZWZvcmUgc3Vic2NyaWJpbmcnXG4gICAgICApO1xuICAgICAgbG9nZ2VyLmVycm9yKCdDYW4gbm90IGZpbmQgdGhpcyBjbGllbnQsIG1ha2Ugc3VyZSB5b3UgY29ubmVjdCB0byBzZXJ2ZXIgYmVmb3JlIHN1YnNjcmliaW5nJyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGNvbnN0IGNsaWVudCA9IHRoaXMuY2xpZW50cy5nZXQocGFyc2VXZWJzb2NrZXQuY2xpZW50SWQpO1xuICAgIGNvbnN0IGNsYXNzTmFtZSA9IHJlcXVlc3QucXVlcnkuY2xhc3NOYW1lO1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB0cmlnZ2VyID0gZ2V0VHJpZ2dlcihjbGFzc05hbWUsICdiZWZvcmVTdWJzY3JpYmUnLCBQYXJzZS5hcHBsaWNhdGlvbklkKTtcbiAgICAgIGlmICh0cmlnZ2VyKSB7XG4gICAgICAgIGNvbnN0IGF1dGggPSBhd2FpdCB0aGlzLmdldEF1dGhGcm9tQ2xpZW50KGNsaWVudCwgcmVxdWVzdC5yZXF1ZXN0SWQsIHJlcXVlc3Quc2Vzc2lvblRva2VuKTtcbiAgICAgICAgaWYgKGF1dGggJiYgYXV0aC51c2VyKSB7XG4gICAgICAgICAgcmVxdWVzdC51c2VyID0gYXV0aC51c2VyO1xuICAgICAgICB9XG5cbiAgICAgICAgY29uc3QgcGFyc2VRdWVyeSA9IG5ldyBQYXJzZS5RdWVyeShjbGFzc05hbWUpO1xuICAgICAgICBwYXJzZVF1ZXJ5LndpdGhKU09OKHJlcXVlc3QucXVlcnkpO1xuICAgICAgICByZXF1ZXN0LnF1ZXJ5ID0gcGFyc2VRdWVyeTtcbiAgICAgICAgYXdhaXQgcnVuVHJpZ2dlcih0cmlnZ2VyLCBgYmVmb3JlU3Vic2NyaWJlLiR7Y2xhc3NOYW1lfWAsIHJlcXVlc3QsIGF1dGgpO1xuXG4gICAgICAgIGNvbnN0IHF1ZXJ5ID0gcmVxdWVzdC5xdWVyeS50b0pTT04oKTtcbiAgICAgICAgaWYgKHF1ZXJ5LmtleXMpIHtcbiAgICAgICAgICBxdWVyeS5maWVsZHMgPSBxdWVyeS5rZXlzLnNwbGl0KCcsJyk7XG4gICAgICAgIH1cbiAgICAgICAgcmVxdWVzdC5xdWVyeSA9IHF1ZXJ5O1xuICAgICAgfVxuXG4gICAgICAvLyBHZXQgc3Vic2NyaXB0aW9uIGZyb20gc3Vic2NyaXB0aW9ucywgY3JlYXRlIG9uZSBpZiBuZWNlc3NhcnlcbiAgICAgIGNvbnN0IHN1YnNjcmlwdGlvbkhhc2ggPSBxdWVyeUhhc2gocmVxdWVzdC5xdWVyeSk7XG4gICAgICAvLyBBZGQgY2xhc3NOYW1lIHRvIHN1YnNjcmlwdGlvbnMgaWYgbmVjZXNzYXJ5XG5cbiAgICAgIGlmICghdGhpcy5zdWJzY3JpcHRpb25zLmhhcyhjbGFzc05hbWUpKSB7XG4gICAgICAgIHRoaXMuc3Vic2NyaXB0aW9ucy5zZXQoY2xhc3NOYW1lLCBuZXcgTWFwKCkpO1xuICAgICAgfVxuICAgICAgY29uc3QgY2xhc3NTdWJzY3JpcHRpb25zID0gdGhpcy5zdWJzY3JpcHRpb25zLmdldChjbGFzc05hbWUpO1xuICAgICAgbGV0IHN1YnNjcmlwdGlvbjtcbiAgICAgIGlmIChjbGFzc1N1YnNjcmlwdGlvbnMuaGFzKHN1YnNjcmlwdGlvbkhhc2gpKSB7XG4gICAgICAgIHN1YnNjcmlwdGlvbiA9IGNsYXNzU3Vic2NyaXB0aW9ucy5nZXQoc3Vic2NyaXB0aW9uSGFzaCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBzdWJzY3JpcHRpb24gPSBuZXcgU3Vic2NyaXB0aW9uKGNsYXNzTmFtZSwgcmVxdWVzdC5xdWVyeS53aGVyZSwgc3Vic2NyaXB0aW9uSGFzaCk7XG4gICAgICAgIGNsYXNzU3Vic2NyaXB0aW9ucy5zZXQoc3Vic2NyaXB0aW9uSGFzaCwgc3Vic2NyaXB0aW9uKTtcbiAgICAgIH1cblxuICAgICAgLy8gQWRkIHN1YnNjcmlwdGlvbkluZm8gdG8gY2xpZW50XG4gICAgICBjb25zdCBzdWJzY3JpcHRpb25JbmZvID0ge1xuICAgICAgICBzdWJzY3JpcHRpb246IHN1YnNjcmlwdGlvbixcbiAgICAgIH07XG4gICAgICAvLyBBZGQgc2VsZWN0ZWQgZmllbGRzLCBzZXNzaW9uVG9rZW4gYW5kIGluc3RhbGxhdGlvbklkIGZvciB0aGlzIHN1YnNjcmlwdGlvbiBpZiBuZWNlc3NhcnlcbiAgICAgIGlmIChyZXF1ZXN0LnF1ZXJ5LmZpZWxkcykge1xuICAgICAgICBzdWJzY3JpcHRpb25JbmZvLmZpZWxkcyA9IHJlcXVlc3QucXVlcnkuZmllbGRzO1xuICAgICAgfVxuICAgICAgaWYgKHJlcXVlc3Quc2Vzc2lvblRva2VuKSB7XG4gICAgICAgIHN1YnNjcmlwdGlvbkluZm8uc2Vzc2lvblRva2VuID0gcmVxdWVzdC5zZXNzaW9uVG9rZW47XG4gICAgICB9XG4gICAgICBjbGllbnQuYWRkU3Vic2NyaXB0aW9uSW5mbyhyZXF1ZXN0LnJlcXVlc3RJZCwgc3Vic2NyaXB0aW9uSW5mbyk7XG5cbiAgICAgIC8vIEFkZCBjbGllbnRJZCB0byBzdWJzY3JpcHRpb25cbiAgICAgIHN1YnNjcmlwdGlvbi5hZGRDbGllbnRTdWJzY3JpcHRpb24ocGFyc2VXZWJzb2NrZXQuY2xpZW50SWQsIHJlcXVlc3QucmVxdWVzdElkKTtcblxuICAgICAgY2xpZW50LnB1c2hTdWJzY3JpYmUocmVxdWVzdC5yZXF1ZXN0SWQpO1xuXG4gICAgICBsb2dnZXIudmVyYm9zZShcbiAgICAgICAgYENyZWF0ZSBjbGllbnQgJHtwYXJzZVdlYnNvY2tldC5jbGllbnRJZH0gbmV3IHN1YnNjcmlwdGlvbjogJHtyZXF1ZXN0LnJlcXVlc3RJZH1gXG4gICAgICApO1xuICAgICAgbG9nZ2VyLnZlcmJvc2UoJ0N1cnJlbnQgY2xpZW50IG51bWJlcjogJWQnLCB0aGlzLmNsaWVudHMuc2l6ZSk7XG4gICAgICBydW5MaXZlUXVlcnlFdmVudEhhbmRsZXJzKHtcbiAgICAgICAgY2xpZW50LFxuICAgICAgICBldmVudDogJ3N1YnNjcmliZScsXG4gICAgICAgIGNsaWVudHM6IHRoaXMuY2xpZW50cy5zaXplLFxuICAgICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICAgICAgc2Vzc2lvblRva2VuOiByZXF1ZXN0LnNlc3Npb25Ub2tlbixcbiAgICAgICAgdXNlTWFzdGVyS2V5OiBjbGllbnQuaGFzTWFzdGVyS2V5LFxuICAgICAgICBpbnN0YWxsYXRpb25JZDogY2xpZW50Lmluc3RhbGxhdGlvbklkLFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgQ2xpZW50LnB1c2hFcnJvcihwYXJzZVdlYnNvY2tldCwgZS5jb2RlIHx8IDE0MSwgZS5tZXNzYWdlIHx8IGUsIGZhbHNlLCByZXF1ZXN0LnJlcXVlc3RJZCk7XG4gICAgICBsb2dnZXIuZXJyb3IoXG4gICAgICAgIGBGYWlsZWQgcnVubmluZyBiZWZvcmVTdWJzY3JpYmUgb24gJHtjbGFzc05hbWV9IGZvciBzZXNzaW9uICR7cmVxdWVzdC5zZXNzaW9uVG9rZW59IHdpdGg6XFxuIEVycm9yOiBgICtcbiAgICAgICAgICBKU09OLnN0cmluZ2lmeShlKVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICBfaGFuZGxlVXBkYXRlU3Vic2NyaXB0aW9uKHBhcnNlV2Vic29ja2V0OiBhbnksIHJlcXVlc3Q6IGFueSk6IGFueSB7XG4gICAgdGhpcy5faGFuZGxlVW5zdWJzY3JpYmUocGFyc2VXZWJzb2NrZXQsIHJlcXVlc3QsIGZhbHNlKTtcbiAgICB0aGlzLl9oYW5kbGVTdWJzY3JpYmUocGFyc2VXZWJzb2NrZXQsIHJlcXVlc3QpO1xuICB9XG5cbiAgX2hhbmRsZVVuc3Vic2NyaWJlKHBhcnNlV2Vic29ja2V0OiBhbnksIHJlcXVlc3Q6IGFueSwgbm90aWZ5Q2xpZW50OiBib29sZWFuID0gdHJ1ZSk6IGFueSB7XG4gICAgLy8gSWYgd2UgY2FuIG5vdCBmaW5kIHRoaXMgY2xpZW50LCByZXR1cm4gZXJyb3IgdG8gY2xpZW50XG4gICAgaWYgKCFPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocGFyc2VXZWJzb2NrZXQsICdjbGllbnRJZCcpKSB7XG4gICAgICBDbGllbnQucHVzaEVycm9yKFxuICAgICAgICBwYXJzZVdlYnNvY2tldCxcbiAgICAgICAgMixcbiAgICAgICAgJ0NhbiBub3QgZmluZCB0aGlzIGNsaWVudCwgbWFrZSBzdXJlIHlvdSBjb25uZWN0IHRvIHNlcnZlciBiZWZvcmUgdW5zdWJzY3JpYmluZydcbiAgICAgICk7XG4gICAgICBsb2dnZXIuZXJyb3IoXG4gICAgICAgICdDYW4gbm90IGZpbmQgdGhpcyBjbGllbnQsIG1ha2Ugc3VyZSB5b3UgY29ubmVjdCB0byBzZXJ2ZXIgYmVmb3JlIHVuc3Vic2NyaWJpbmcnXG4gICAgICApO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBjb25zdCByZXF1ZXN0SWQgPSByZXF1ZXN0LnJlcXVlc3RJZDtcbiAgICBjb25zdCBjbGllbnQgPSB0aGlzLmNsaWVudHMuZ2V0KHBhcnNlV2Vic29ja2V0LmNsaWVudElkKTtcbiAgICBpZiAodHlwZW9mIGNsaWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIENsaWVudC5wdXNoRXJyb3IoXG4gICAgICAgIHBhcnNlV2Vic29ja2V0LFxuICAgICAgICAyLFxuICAgICAgICAnQ2Fubm90IGZpbmQgY2xpZW50IHdpdGggY2xpZW50SWQgJyArXG4gICAgICAgICAgcGFyc2VXZWJzb2NrZXQuY2xpZW50SWQgK1xuICAgICAgICAgICcuIE1ha2Ugc3VyZSB5b3UgY29ubmVjdCB0byBsaXZlIHF1ZXJ5IHNlcnZlciBiZWZvcmUgdW5zdWJzY3JpYmluZy4nXG4gICAgICApO1xuICAgICAgbG9nZ2VyLmVycm9yKCdDYW4gbm90IGZpbmQgdGhpcyBjbGllbnQgJyArIHBhcnNlV2Vic29ja2V0LmNsaWVudElkKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBzdWJzY3JpcHRpb25JbmZvID0gY2xpZW50LmdldFN1YnNjcmlwdGlvbkluZm8ocmVxdWVzdElkKTtcbiAgICBpZiAodHlwZW9mIHN1YnNjcmlwdGlvbkluZm8gPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICBDbGllbnQucHVzaEVycm9yKFxuICAgICAgICBwYXJzZVdlYnNvY2tldCxcbiAgICAgICAgMixcbiAgICAgICAgJ0Nhbm5vdCBmaW5kIHN1YnNjcmlwdGlvbiB3aXRoIGNsaWVudElkICcgK1xuICAgICAgICAgIHBhcnNlV2Vic29ja2V0LmNsaWVudElkICtcbiAgICAgICAgICAnIHN1YnNjcmlwdGlvbklkICcgK1xuICAgICAgICAgIHJlcXVlc3RJZCArXG4gICAgICAgICAgJy4gTWFrZSBzdXJlIHlvdSBzdWJzY3JpYmUgdG8gbGl2ZSBxdWVyeSBzZXJ2ZXIgYmVmb3JlIHVuc3Vic2NyaWJpbmcuJ1xuICAgICAgKTtcbiAgICAgIGxvZ2dlci5lcnJvcihcbiAgICAgICAgJ0NhbiBub3QgZmluZCBzdWJzY3JpcHRpb24gd2l0aCBjbGllbnRJZCAnICtcbiAgICAgICAgICBwYXJzZVdlYnNvY2tldC5jbGllbnRJZCArXG4gICAgICAgICAgJyBzdWJzY3JpcHRpb25JZCAnICtcbiAgICAgICAgICByZXF1ZXN0SWRcbiAgICAgICk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gUmVtb3ZlIHN1YnNjcmlwdGlvbiBmcm9tIGNsaWVudFxuICAgIGNsaWVudC5kZWxldGVTdWJzY3JpcHRpb25JbmZvKHJlcXVlc3RJZCk7XG4gICAgLy8gUmVtb3ZlIGNsaWVudCBmcm9tIHN1YnNjcmlwdGlvblxuICAgIGNvbnN0IHN1YnNjcmlwdGlvbiA9IHN1YnNjcmlwdGlvbkluZm8uc3Vic2NyaXB0aW9uO1xuICAgIGNvbnN0IGNsYXNzTmFtZSA9IHN1YnNjcmlwdGlvbi5jbGFzc05hbWU7XG4gICAgc3Vic2NyaXB0aW9uLmRlbGV0ZUNsaWVudFN1YnNjcmlwdGlvbihwYXJzZVdlYnNvY2tldC5jbGllbnRJZCwgcmVxdWVzdElkKTtcbiAgICAvLyBJZiB0aGVyZSBpcyBubyBjbGllbnQgd2hpY2ggaXMgc3Vic2NyaWJpbmcgdGhpcyBzdWJzY3JpcHRpb24sIHJlbW92ZSBpdCBmcm9tIHN1YnNjcmlwdGlvbnNcbiAgICBjb25zdCBjbGFzc1N1YnNjcmlwdGlvbnMgPSB0aGlzLnN1YnNjcmlwdGlvbnMuZ2V0KGNsYXNzTmFtZSk7XG4gICAgaWYgKCFzdWJzY3JpcHRpb24uaGFzU3Vic2NyaWJpbmdDbGllbnQoKSkge1xuICAgICAgY2xhc3NTdWJzY3JpcHRpb25zLmRlbGV0ZShzdWJzY3JpcHRpb24uaGFzaCk7XG4gICAgfVxuICAgIC8vIElmIHRoZXJlIGlzIG5vIHN1YnNjcmlwdGlvbnMgdW5kZXIgdGhpcyBjbGFzcywgcmVtb3ZlIGl0IGZyb20gc3Vic2NyaXB0aW9uc1xuICAgIGlmIChjbGFzc1N1YnNjcmlwdGlvbnMuc2l6ZSA9PT0gMCkge1xuICAgICAgdGhpcy5zdWJzY3JpcHRpb25zLmRlbGV0ZShjbGFzc05hbWUpO1xuICAgIH1cbiAgICBydW5MaXZlUXVlcnlFdmVudEhhbmRsZXJzKHtcbiAgICAgIGNsaWVudCxcbiAgICAgIGV2ZW50OiAndW5zdWJzY3JpYmUnLFxuICAgICAgY2xpZW50czogdGhpcy5jbGllbnRzLnNpemUsXG4gICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICAgIHNlc3Npb25Ub2tlbjogc3Vic2NyaXB0aW9uSW5mby5zZXNzaW9uVG9rZW4sXG4gICAgICB1c2VNYXN0ZXJLZXk6IGNsaWVudC5oYXNNYXN0ZXJLZXksXG4gICAgICBpbnN0YWxsYXRpb25JZDogY2xpZW50Lmluc3RhbGxhdGlvbklkLFxuICAgIH0pO1xuXG4gICAgaWYgKCFub3RpZnlDbGllbnQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjbGllbnQucHVzaFVuc3Vic2NyaWJlKHJlcXVlc3QucmVxdWVzdElkKTtcblxuICAgIGxvZ2dlci52ZXJib3NlKFxuICAgICAgYERlbGV0ZSBjbGllbnQ6ICR7cGFyc2VXZWJzb2NrZXQuY2xpZW50SWR9IHwgc3Vic2NyaXB0aW9uOiAke3JlcXVlc3QucmVxdWVzdElkfWBcbiAgICApO1xuICB9XG59XG5cbmV4cG9ydCB7IFBhcnNlTGl2ZVF1ZXJ5U2VydmVyIH07XG4iXX0=