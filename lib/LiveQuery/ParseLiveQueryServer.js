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
              const auth = await this.getAuthForSessionToken(res.sessionToken);
              res.user = auth.user;

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

              const auth = await this.getAuthForSessionToken(res.sessionToken);
              res.user = auth.user;
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
        const auth = await this.getAuthForSessionToken(req.sessionToken);
        req.user = auth.user;
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
        const auth = await this.getAuthForSessionToken(request.sessionToken);
        request.user = auth.user;
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9MaXZlUXVlcnkvUGFyc2VMaXZlUXVlcnlTZXJ2ZXIuanMiXSwibmFtZXMiOlsiUGFyc2VMaXZlUXVlcnlTZXJ2ZXIiLCJjb25zdHJ1Y3RvciIsInNlcnZlciIsImNvbmZpZyIsInBhcnNlU2VydmVyQ29uZmlnIiwiY2xpZW50cyIsIk1hcCIsInN1YnNjcmlwdGlvbnMiLCJhcHBJZCIsIlBhcnNlIiwiYXBwbGljYXRpb25JZCIsIm1hc3RlcktleSIsImtleVBhaXJzIiwia2V5IiwiT2JqZWN0Iiwia2V5cyIsInNldCIsImxvZ2dlciIsInZlcmJvc2UiLCJkaXNhYmxlU2luZ2xlSW5zdGFuY2UiLCJzZXJ2ZXJVUkwiLCJpbml0aWFsaXplIiwiamF2YVNjcmlwdEtleSIsImNhY2hlQ29udHJvbGxlciIsImNhY2hlVGltZW91dCIsImF1dGhDYWNoZSIsIkxSVSIsIm1heCIsIm1heEFnZSIsInBhcnNlV2ViU29ja2V0U2VydmVyIiwiUGFyc2VXZWJTb2NrZXRTZXJ2ZXIiLCJwYXJzZVdlYnNvY2tldCIsIl9vbkNvbm5lY3QiLCJzdWJzY3JpYmVyIiwiUGFyc2VQdWJTdWIiLCJjcmVhdGVTdWJzY3JpYmVyIiwic3Vic2NyaWJlIiwib24iLCJjaGFubmVsIiwibWVzc2FnZVN0ciIsIm1lc3NhZ2UiLCJKU09OIiwicGFyc2UiLCJlIiwiZXJyb3IiLCJfaW5mbGF0ZVBhcnNlT2JqZWN0IiwiX29uQWZ0ZXJTYXZlIiwiX29uQWZ0ZXJEZWxldGUiLCJjdXJyZW50UGFyc2VPYmplY3QiLCJVc2VyUm91dGVyIiwicmVtb3ZlSGlkZGVuUHJvcGVydGllcyIsImNsYXNzTmFtZSIsInBhcnNlT2JqZWN0IiwiX2ZpbmlzaEZldGNoIiwib3JpZ2luYWxQYXJzZU9iamVjdCIsImRlbGV0ZWRQYXJzZU9iamVjdCIsInRvSlNPTiIsImNsYXNzTGV2ZWxQZXJtaXNzaW9ucyIsImlkIiwic2l6ZSIsImNsYXNzU3Vic2NyaXB0aW9ucyIsImdldCIsImRlYnVnIiwic3Vic2NyaXB0aW9uIiwidmFsdWVzIiwiaXNTdWJzY3JpcHRpb25NYXRjaGVkIiwiX21hdGNoZXNTdWJzY3JpcHRpb24iLCJjbGllbnRJZCIsInJlcXVlc3RJZHMiLCJfIiwiZW50cmllcyIsImNsaWVudFJlcXVlc3RJZHMiLCJjbGllbnQiLCJmb3JFYWNoIiwicmVxdWVzdElkIiwiYWNsIiwiZ2V0QUNMIiwib3AiLCJfZ2V0Q0xQT3BlcmF0aW9uIiwicXVlcnkiLCJyZXMiLCJfbWF0Y2hlc0NMUCIsImlzTWF0Y2hlZCIsIl9tYXRjaGVzQUNMIiwiZXZlbnQiLCJzZXNzaW9uVG9rZW4iLCJvYmplY3QiLCJ1c2VNYXN0ZXJLZXkiLCJoYXNNYXN0ZXJLZXkiLCJpbnN0YWxsYXRpb25JZCIsInNlbmRFdmVudCIsInRyaWdnZXIiLCJhdXRoIiwiZ2V0QXV0aEZvclNlc3Npb25Ub2tlbiIsInVzZXIiLCJmcm9tSlNPTiIsInB1c2hEZWxldGUiLCJDbGllbnQiLCJwdXNoRXJyb3IiLCJwYXJzZVdlYlNvY2tldCIsImNvZGUiLCJzdHJpbmdpZnkiLCJpc09yaWdpbmFsU3Vic2NyaXB0aW9uTWF0Y2hlZCIsImlzQ3VycmVudFN1YnNjcmlwdGlvbk1hdGNoZWQiLCJvcmlnaW5hbEFDTENoZWNraW5nUHJvbWlzZSIsIlByb21pc2UiLCJyZXNvbHZlIiwib3JpZ2luYWxBQ0wiLCJjdXJyZW50QUNMQ2hlY2tpbmdQcm9taXNlIiwiY3VycmVudEFDTCIsImlzT3JpZ2luYWxNYXRjaGVkIiwiaXNDdXJyZW50TWF0Y2hlZCIsImFsbCIsImhhc2giLCJ0eXBlIiwib3JpZ2luYWwiLCJmdW5jdGlvbk5hbWUiLCJjaGFyQXQiLCJ0b1VwcGVyQ2FzZSIsInNsaWNlIiwicmVxdWVzdCIsInR2NCIsInZhbGlkYXRlIiwiUmVxdWVzdFNjaGVtYSIsIl9oYW5kbGVDb25uZWN0IiwiX2hhbmRsZVN1YnNjcmliZSIsIl9oYW5kbGVVcGRhdGVTdWJzY3JpcHRpb24iLCJfaGFuZGxlVW5zdWJzY3JpYmUiLCJpbmZvIiwiaGFzIiwiZGVsZXRlIiwic3Vic2NyaXB0aW9uSW5mbyIsInN1YnNjcmlwdGlvbkluZm9zIiwiZGVsZXRlQ2xpZW50U3Vic2NyaXB0aW9uIiwiaGFzU3Vic2NyaWJpbmdDbGllbnQiLCJmcm9tQ2FjaGUiLCJhdXRoUHJvbWlzZSIsInRoZW4iLCJ1c2VySWQiLCJjYXRjaCIsInJlc3VsdCIsIkVycm9yIiwiSU5WQUxJRF9TRVNTSU9OX1RPS0VOIiwiZGVsIiwiZ2V0U3Vic2NyaXB0aW9uSW5mbyIsImFjbEdyb3VwIiwicHVzaCIsIlNjaGVtYUNvbnRyb2xsZXIiLCJ2YWxpZGF0ZVBlcm1pc3Npb24iLCJsZW5ndGgiLCJvYmplY3RJZCIsIl92ZXJpZnlBQ0wiLCJ0b2tlbiIsImlzU3Vic2NyaXB0aW9uU2Vzc2lvblRva2VuTWF0Y2hlZCIsImdldFJlYWRBY2Nlc3MiLCJhY2xfaGFzX3JvbGVzIiwicGVybWlzc2lvbnNCeUlkIiwic29tZSIsInN0YXJ0c1dpdGgiLCJyb2xlTmFtZXMiLCJnZXRVc2VyUm9sZXMiLCJyb2xlIiwiZ2V0UHVibGljUmVhZEFjY2VzcyIsInN1YnNjcmlwdGlvblRva2VuIiwiY2xpZW50U2Vzc2lvblRva2VuIiwiX3ZhbGlkYXRlS2V5cyIsIl9oYXNNYXN0ZXJLZXkiLCJyZXEiLCJwdXNoQ29ubmVjdCIsInZhbGlkS2V5UGFpcnMiLCJwcm90b3R5cGUiLCJoYXNPd25Qcm9wZXJ0eSIsImNhbGwiLCJpc1ZhbGlkIiwic2VjcmV0IiwicGFyc2VRdWVyeSIsIlF1ZXJ5Iiwid2l0aEpTT04iLCJmaWVsZHMiLCJzcGxpdCIsInN1YnNjcmlwdGlvbkhhc2giLCJTdWJzY3JpcHRpb24iLCJ3aGVyZSIsImFkZFN1YnNjcmlwdGlvbkluZm8iLCJhZGRDbGllbnRTdWJzY3JpcHRpb24iLCJwdXNoU3Vic2NyaWJlIiwibm90aWZ5Q2xpZW50IiwiZGVsZXRlU3Vic2NyaXB0aW9uSW5mbyIsInB1c2hVbnN1YnNjcmliZSJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNB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LENBQUNELElBQW5CLEtBQTRCLENBQWhDLEVBQW1DO0FBQ2pDLFdBQUtwRCxhQUFMLENBQW1CMkgsTUFBbkIsQ0FBMEIvRSxTQUExQjtBQUNEOztBQUNELDZDQUEwQjtBQUN4QnFCLE1BQUFBLE1BRHdCO0FBRXhCWSxNQUFBQSxLQUFLLEVBQUUsYUFGaUI7QUFHeEIvRSxNQUFBQSxPQUFPLEVBQUUsS0FBS0EsT0FBTCxDQUFhc0QsSUFIRTtBQUl4QnBELE1BQUFBLGFBQWEsRUFBRSxLQUFLQSxhQUFMLENBQW1Cb0QsSUFKVjtBQUt4QjBCLE1BQUFBLFlBQVksRUFBRThDLGdCQUFnQixDQUFDOUMsWUFMUDtBQU14QkUsTUFBQUEsWUFBWSxFQUFFZixNQUFNLENBQUNnQixZQU5HO0FBT3hCQyxNQUFBQSxjQUFjLEVBQUVqQixNQUFNLENBQUNpQjtBQVBDLEtBQTFCOztBQVVBLFFBQUksQ0FBQ2lHLFlBQUwsRUFBbUI7QUFDakI7QUFDRDs7QUFFRGxILElBQUFBLE1BQU0sQ0FBQ29ILGVBQVAsQ0FBdUJwRSxPQUFPLENBQUM5QyxTQUEvQjs7QUFFQXpELG9CQUFPQyxPQUFQLENBQ0csa0JBQWlCYSxjQUFjLENBQUNvQyxRQUFTLG9CQUFtQnFELE9BQU8sQ0FBQzlDLFNBQVUsRUFEakY7QUFHRDs7QUEvekJ3QiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB0djQgZnJvbSAndHY0JztcbmltcG9ydCBQYXJzZSBmcm9tICdwYXJzZS9ub2RlJztcbmltcG9ydCB7IFN1YnNjcmlwdGlvbiB9IGZyb20gJy4vU3Vic2NyaXB0aW9uJztcbmltcG9ydCB7IENsaWVudCB9IGZyb20gJy4vQ2xpZW50JztcbmltcG9ydCB7IFBhcnNlV2ViU29ja2V0U2VydmVyIH0gZnJvbSAnLi9QYXJzZVdlYlNvY2tldFNlcnZlcic7XG5pbXBvcnQgbG9nZ2VyIGZyb20gJy4uL2xvZ2dlcic7XG5pbXBvcnQgUmVxdWVzdFNjaGVtYSBmcm9tICcuL1JlcXVlc3RTY2hlbWEnO1xuaW1wb3J0IHsgbWF0Y2hlc1F1ZXJ5LCBxdWVyeUhhc2ggfSBmcm9tICcuL1F1ZXJ5VG9vbHMnO1xuaW1wb3J0IHsgUGFyc2VQdWJTdWIgfSBmcm9tICcuL1BhcnNlUHViU3ViJztcbmltcG9ydCBTY2hlbWFDb250cm9sbGVyIGZyb20gJy4uL0NvbnRyb2xsZXJzL1NjaGVtYUNvbnRyb2xsZXInO1xuaW1wb3J0IF8gZnJvbSAnbG9kYXNoJztcbmltcG9ydCB7IHY0IGFzIHV1aWR2NCB9IGZyb20gJ3V1aWQnO1xuaW1wb3J0IHsgcnVuTGl2ZVF1ZXJ5RXZlbnRIYW5kbGVycywgZ2V0VHJpZ2dlciwgcnVuVHJpZ2dlciB9IGZyb20gJy4uL3RyaWdnZXJzJztcbmltcG9ydCB7IGdldEF1dGhGb3JTZXNzaW9uVG9rZW4sIEF1dGggfSBmcm9tICcuLi9BdXRoJztcbmltcG9ydCB7IGdldENhY2hlQ29udHJvbGxlciB9IGZyb20gJy4uL0NvbnRyb2xsZXJzJztcbmltcG9ydCBMUlUgZnJvbSAnbHJ1LWNhY2hlJztcbmltcG9ydCBVc2VyUm91dGVyIGZyb20gJy4uL1JvdXRlcnMvVXNlcnNSb3V0ZXInO1xuXG5jbGFzcyBQYXJzZUxpdmVRdWVyeVNlcnZlciB7XG4gIGNsaWVudHM6IE1hcDtcbiAgLy8gY2xhc3NOYW1lIC0+IChxdWVyeUhhc2ggLT4gc3Vic2NyaXB0aW9uKVxuICBzdWJzY3JpcHRpb25zOiBPYmplY3Q7XG4gIHBhcnNlV2ViU29ja2V0U2VydmVyOiBPYmplY3Q7XG4gIGtleVBhaXJzOiBhbnk7XG4gIC8vIFRoZSBzdWJzY3JpYmVyIHdlIHVzZSB0byBnZXQgb2JqZWN0IHVwZGF0ZSBmcm9tIHB1Ymxpc2hlclxuICBzdWJzY3JpYmVyOiBPYmplY3Q7XG5cbiAgY29uc3RydWN0b3Ioc2VydmVyOiBhbnksIGNvbmZpZzogYW55ID0ge30sIHBhcnNlU2VydmVyQ29uZmlnOiBhbnkgPSB7fSkge1xuICAgIHRoaXMuc2VydmVyID0gc2VydmVyO1xuICAgIHRoaXMuY2xpZW50cyA9IG5ldyBNYXAoKTtcbiAgICB0aGlzLnN1YnNjcmlwdGlvbnMgPSBuZXcgTWFwKCk7XG4gICAgdGhpcy5jb25maWcgPSBjb25maWc7XG5cbiAgICBjb25maWcuYXBwSWQgPSBjb25maWcuYXBwSWQgfHwgUGFyc2UuYXBwbGljYXRpb25JZDtcbiAgICBjb25maWcubWFzdGVyS2V5ID0gY29uZmlnLm1hc3RlcktleSB8fCBQYXJzZS5tYXN0ZXJLZXk7XG5cbiAgICAvLyBTdG9yZSBrZXlzLCBjb252ZXJ0IG9iaiB0byBtYXBcbiAgICBjb25zdCBrZXlQYWlycyA9IGNvbmZpZy5rZXlQYWlycyB8fCB7fTtcbiAgICB0aGlzLmtleVBhaXJzID0gbmV3IE1hcCgpO1xuICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5rZXlzKGtleVBhaXJzKSkge1xuICAgICAgdGhpcy5rZXlQYWlycy5zZXQoa2V5LCBrZXlQYWlyc1trZXldKTtcbiAgICB9XG4gICAgbG9nZ2VyLnZlcmJvc2UoJ1N1cHBvcnQga2V5IHBhaXJzJywgdGhpcy5rZXlQYWlycyk7XG5cbiAgICAvLyBJbml0aWFsaXplIFBhcnNlXG4gICAgUGFyc2UuT2JqZWN0LmRpc2FibGVTaW5nbGVJbnN0YW5jZSgpO1xuICAgIGNvbnN0IHNlcnZlclVSTCA9IGNvbmZpZy5zZXJ2ZXJVUkwgfHwgUGFyc2Uuc2VydmVyVVJMO1xuICAgIFBhcnNlLnNlcnZlclVSTCA9IHNlcnZlclVSTDtcbiAgICBQYXJzZS5pbml0aWFsaXplKGNvbmZpZy5hcHBJZCwgUGFyc2UuamF2YVNjcmlwdEtleSwgY29uZmlnLm1hc3RlcktleSk7XG5cbiAgICAvLyBUaGUgY2FjaGUgY29udHJvbGxlciBpcyBhIHByb3BlciBjYWNoZSBjb250cm9sbGVyXG4gICAgLy8gd2l0aCBhY2Nlc3MgdG8gVXNlciBhbmQgUm9sZXNcbiAgICB0aGlzLmNhY2hlQ29udHJvbGxlciA9IGdldENhY2hlQ29udHJvbGxlcihwYXJzZVNlcnZlckNvbmZpZyk7XG5cbiAgICBjb25maWcuY2FjaGVUaW1lb3V0ID0gY29uZmlnLmNhY2hlVGltZW91dCB8fCA1ICogMTAwMDsgLy8gNXNcblxuICAgIC8vIFRoaXMgYXV0aCBjYWNoZSBzdG9yZXMgdGhlIHByb21pc2VzIGZvciBlYWNoIGF1dGggcmVzb2x1dGlvbi5cbiAgICAvLyBUaGUgbWFpbiBiZW5lZml0IGlzIHRvIGJlIGFibGUgdG8gcmV1c2UgdGhlIHNhbWUgdXNlciAvIHNlc3Npb24gdG9rZW4gcmVzb2x1dGlvbi5cbiAgICB0aGlzLmF1dGhDYWNoZSA9IG5ldyBMUlUoe1xuICAgICAgbWF4OiA1MDAsIC8vIDUwMCBjb25jdXJyZW50XG4gICAgICBtYXhBZ2U6IGNvbmZpZy5jYWNoZVRpbWVvdXQsXG4gICAgfSk7XG4gICAgLy8gSW5pdGlhbGl6ZSB3ZWJzb2NrZXQgc2VydmVyXG4gICAgdGhpcy5wYXJzZVdlYlNvY2tldFNlcnZlciA9IG5ldyBQYXJzZVdlYlNvY2tldFNlcnZlcihcbiAgICAgIHNlcnZlcixcbiAgICAgIHBhcnNlV2Vic29ja2V0ID0+IHRoaXMuX29uQ29ubmVjdChwYXJzZVdlYnNvY2tldCksXG4gICAgICBjb25maWdcbiAgICApO1xuXG4gICAgLy8gSW5pdGlhbGl6ZSBzdWJzY3JpYmVyXG4gICAgdGhpcy5zdWJzY3JpYmVyID0gUGFyc2VQdWJTdWIuY3JlYXRlU3Vic2NyaWJlcihjb25maWcpO1xuICAgIHRoaXMuc3Vic2NyaWJlci5zdWJzY3JpYmUoUGFyc2UuYXBwbGljYXRpb25JZCArICdhZnRlclNhdmUnKTtcbiAgICB0aGlzLnN1YnNjcmliZXIuc3Vic2NyaWJlKFBhcnNlLmFwcGxpY2F0aW9uSWQgKyAnYWZ0ZXJEZWxldGUnKTtcbiAgICAvLyBSZWdpc3RlciBtZXNzYWdlIGhhbmRsZXIgZm9yIHN1YnNjcmliZXIuIFdoZW4gcHVibGlzaGVyIGdldCBtZXNzYWdlcywgaXQgd2lsbCBwdWJsaXNoIG1lc3NhZ2VcbiAgICAvLyB0byB0aGUgc3Vic2NyaWJlcnMgYW5kIHRoZSBoYW5kbGVyIHdpbGwgYmUgY2FsbGVkLlxuICAgIHRoaXMuc3Vic2NyaWJlci5vbignbWVzc2FnZScsIChjaGFubmVsLCBtZXNzYWdlU3RyKSA9PiB7XG4gICAgICBsb2dnZXIudmVyYm9zZSgnU3Vic2NyaWJlIG1lc3NhZ2UgJWonLCBtZXNzYWdlU3RyKTtcbiAgICAgIGxldCBtZXNzYWdlO1xuICAgICAgdHJ5IHtcbiAgICAgICAgbWVzc2FnZSA9IEpTT04ucGFyc2UobWVzc2FnZVN0cik7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGxvZ2dlci5lcnJvcigndW5hYmxlIHRvIHBhcnNlIG1lc3NhZ2UnLCBtZXNzYWdlU3RyLCBlKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgICAgdGhpcy5faW5mbGF0ZVBhcnNlT2JqZWN0KG1lc3NhZ2UpO1xuICAgICAgaWYgKGNoYW5uZWwgPT09IFBhcnNlLmFwcGxpY2F0aW9uSWQgKyAnYWZ0ZXJTYXZlJykge1xuICAgICAgICB0aGlzLl9vbkFmdGVyU2F2ZShtZXNzYWdlKTtcbiAgICAgIH0gZWxzZSBpZiAoY2hhbm5lbCA9PT0gUGFyc2UuYXBwbGljYXRpb25JZCArICdhZnRlckRlbGV0ZScpIHtcbiAgICAgICAgdGhpcy5fb25BZnRlckRlbGV0ZShtZXNzYWdlKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGxvZ2dlci5lcnJvcignR2V0IG1lc3NhZ2UgJXMgZnJvbSB1bmtub3duIGNoYW5uZWwgJWonLCBtZXNzYWdlLCBjaGFubmVsKTtcbiAgICAgIH1cbiAgICB9KTtcbiAgfVxuXG4gIC8vIE1lc3NhZ2UgaXMgdGhlIEpTT04gb2JqZWN0IGZyb20gcHVibGlzaGVyLiBNZXNzYWdlLmN1cnJlbnRQYXJzZU9iamVjdCBpcyB0aGUgUGFyc2VPYmplY3QgSlNPTiBhZnRlciBjaGFuZ2VzLlxuICAvLyBNZXNzYWdlLm9yaWdpbmFsUGFyc2VPYmplY3QgaXMgdGhlIG9yaWdpbmFsIFBhcnNlT2JqZWN0IEpTT04uXG4gIF9pbmZsYXRlUGFyc2VPYmplY3QobWVzc2FnZTogYW55KTogdm9pZCB7XG4gICAgLy8gSW5mbGF0ZSBtZXJnZWQgb2JqZWN0XG4gICAgY29uc3QgY3VycmVudFBhcnNlT2JqZWN0ID0gbWVzc2FnZS5jdXJyZW50UGFyc2VPYmplY3Q7XG4gICAgVXNlclJvdXRlci5yZW1vdmVIaWRkZW5Qcm9wZXJ0aWVzKGN1cnJlbnRQYXJzZU9iamVjdCk7XG4gICAgbGV0IGNsYXNzTmFtZSA9IGN1cnJlbnRQYXJzZU9iamVjdC5jbGFzc05hbWU7XG4gICAgbGV0IHBhcnNlT2JqZWN0ID0gbmV3IFBhcnNlLk9iamVjdChjbGFzc05hbWUpO1xuICAgIHBhcnNlT2JqZWN0Ll9maW5pc2hGZXRjaChjdXJyZW50UGFyc2VPYmplY3QpO1xuICAgIG1lc3NhZ2UuY3VycmVudFBhcnNlT2JqZWN0ID0gcGFyc2VPYmplY3Q7XG4gICAgLy8gSW5mbGF0ZSBvcmlnaW5hbCBvYmplY3RcbiAgICBjb25zdCBvcmlnaW5hbFBhcnNlT2JqZWN0ID0gbWVzc2FnZS5vcmlnaW5hbFBhcnNlT2JqZWN0O1xuICAgIGlmIChvcmlnaW5hbFBhcnNlT2JqZWN0KSB7XG4gICAgICBVc2VyUm91dGVyLnJlbW92ZUhpZGRlblByb3BlcnRpZXMob3JpZ2luYWxQYXJzZU9iamVjdCk7XG4gICAgICBjbGFzc05hbWUgPSBvcmlnaW5hbFBhcnNlT2JqZWN0LmNsYXNzTmFtZTtcbiAgICAgIHBhcnNlT2JqZWN0ID0gbmV3IFBhcnNlLk9iamVjdChjbGFzc05hbWUpO1xuICAgICAgcGFyc2VPYmplY3QuX2ZpbmlzaEZldGNoKG9yaWdpbmFsUGFyc2VPYmplY3QpO1xuICAgICAgbWVzc2FnZS5vcmlnaW5hbFBhcnNlT2JqZWN0ID0gcGFyc2VPYmplY3Q7XG4gICAgfVxuICB9XG5cbiAgLy8gTWVzc2FnZSBpcyB0aGUgSlNPTiBvYmplY3QgZnJvbSBwdWJsaXNoZXIgYWZ0ZXIgaW5mbGF0ZWQuIE1lc3NhZ2UuY3VycmVudFBhcnNlT2JqZWN0IGlzIHRoZSBQYXJzZU9iamVjdCBhZnRlciBjaGFuZ2VzLlxuICAvLyBNZXNzYWdlLm9yaWdpbmFsUGFyc2VPYmplY3QgaXMgdGhlIG9yaWdpbmFsIFBhcnNlT2JqZWN0LlxuICBhc3luYyBfb25BZnRlckRlbGV0ZShtZXNzYWdlOiBhbnkpOiB2b2lkIHtcbiAgICBsb2dnZXIudmVyYm9zZShQYXJzZS5hcHBsaWNhdGlvbklkICsgJ2FmdGVyRGVsZXRlIGlzIHRyaWdnZXJlZCcpO1xuXG4gICAgbGV0IGRlbGV0ZWRQYXJzZU9iamVjdCA9IG1lc3NhZ2UuY3VycmVudFBhcnNlT2JqZWN0LnRvSlNPTigpO1xuICAgIGNvbnN0IGNsYXNzTGV2ZWxQZXJtaXNzaW9ucyA9IG1lc3NhZ2UuY2xhc3NMZXZlbFBlcm1pc3Npb25zO1xuICAgIGNvbnN0IGNsYXNzTmFtZSA9IGRlbGV0ZWRQYXJzZU9iamVjdC5jbGFzc05hbWU7XG4gICAgbG9nZ2VyLnZlcmJvc2UoJ0NsYXNzTmFtZTogJWogfCBPYmplY3RJZDogJXMnLCBjbGFzc05hbWUsIGRlbGV0ZWRQYXJzZU9iamVjdC5pZCk7XG4gICAgbG9nZ2VyLnZlcmJvc2UoJ0N1cnJlbnQgY2xpZW50IG51bWJlciA6ICVkJywgdGhpcy5jbGllbnRzLnNpemUpO1xuXG4gICAgY29uc3QgY2xhc3NTdWJzY3JpcHRpb25zID0gdGhpcy5zdWJzY3JpcHRpb25zLmdldChjbGFzc05hbWUpO1xuICAgIGlmICh0eXBlb2YgY2xhc3NTdWJzY3JpcHRpb25zID09PSAndW5kZWZpbmVkJykge1xuICAgICAgbG9nZ2VyLmRlYnVnKCdDYW4gbm90IGZpbmQgc3Vic2NyaXB0aW9ucyB1bmRlciB0aGlzIGNsYXNzICcgKyBjbGFzc05hbWUpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGZvciAoY29uc3Qgc3Vic2NyaXB0aW9uIG9mIGNsYXNzU3Vic2NyaXB0aW9ucy52YWx1ZXMoKSkge1xuICAgICAgY29uc3QgaXNTdWJzY3JpcHRpb25NYXRjaGVkID0gdGhpcy5fbWF0Y2hlc1N1YnNjcmlwdGlvbihkZWxldGVkUGFyc2VPYmplY3QsIHN1YnNjcmlwdGlvbik7XG4gICAgICBpZiAoIWlzU3Vic2NyaXB0aW9uTWF0Y2hlZCkge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cbiAgICAgIGZvciAoY29uc3QgW2NsaWVudElkLCByZXF1ZXN0SWRzXSBvZiBfLmVudHJpZXMoc3Vic2NyaXB0aW9uLmNsaWVudFJlcXVlc3RJZHMpKSB7XG4gICAgICAgIGNvbnN0IGNsaWVudCA9IHRoaXMuY2xpZW50cy5nZXQoY2xpZW50SWQpO1xuICAgICAgICBpZiAodHlwZW9mIGNsaWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgfVxuICAgICAgICByZXF1ZXN0SWRzLmZvckVhY2goYXN5bmMgcmVxdWVzdElkID0+IHtcbiAgICAgICAgICBjb25zdCBhY2wgPSBtZXNzYWdlLmN1cnJlbnRQYXJzZU9iamVjdC5nZXRBQ0woKTtcbiAgICAgICAgICAvLyBDaGVjayBDTFBcbiAgICAgICAgICBjb25zdCBvcCA9IHRoaXMuX2dldENMUE9wZXJhdGlvbihzdWJzY3JpcHRpb24ucXVlcnkpO1xuICAgICAgICAgIGxldCByZXMgPSB7fTtcbiAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5fbWF0Y2hlc0NMUChcbiAgICAgICAgICAgICAgY2xhc3NMZXZlbFBlcm1pc3Npb25zLFxuICAgICAgICAgICAgICBtZXNzYWdlLmN1cnJlbnRQYXJzZU9iamVjdCxcbiAgICAgICAgICAgICAgY2xpZW50LFxuICAgICAgICAgICAgICByZXF1ZXN0SWQsXG4gICAgICAgICAgICAgIG9wXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgY29uc3QgaXNNYXRjaGVkID0gYXdhaXQgdGhpcy5fbWF0Y2hlc0FDTChhY2wsIGNsaWVudCwgcmVxdWVzdElkKTtcbiAgICAgICAgICAgIGlmICghaXNNYXRjaGVkKSB7XG4gICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmVzID0ge1xuICAgICAgICAgICAgICBldmVudDogJ2RlbGV0ZScsXG4gICAgICAgICAgICAgIHNlc3Npb25Ub2tlbjogY2xpZW50LnNlc3Npb25Ub2tlbixcbiAgICAgICAgICAgICAgb2JqZWN0OiBkZWxldGVkUGFyc2VPYmplY3QsXG4gICAgICAgICAgICAgIGNsaWVudHM6IHRoaXMuY2xpZW50cy5zaXplLFxuICAgICAgICAgICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICAgICAgICAgICAgdXNlTWFzdGVyS2V5OiBjbGllbnQuaGFzTWFzdGVyS2V5LFxuICAgICAgICAgICAgICBpbnN0YWxsYXRpb25JZDogY2xpZW50Lmluc3RhbGxhdGlvbklkLFxuICAgICAgICAgICAgICBzZW5kRXZlbnQ6IHRydWUsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgY29uc3QgdHJpZ2dlciA9IGdldFRyaWdnZXIoY2xhc3NOYW1lLCAnYWZ0ZXJFdmVudCcsIFBhcnNlLmFwcGxpY2F0aW9uSWQpO1xuICAgICAgICAgICAgaWYgKHRyaWdnZXIpIHtcbiAgICAgICAgICAgICAgY29uc3QgYXV0aCA9IGF3YWl0IHRoaXMuZ2V0QXV0aEZvclNlc3Npb25Ub2tlbihyZXMuc2Vzc2lvblRva2VuKTtcbiAgICAgICAgICAgICAgcmVzLnVzZXIgPSBhdXRoLnVzZXI7XG4gICAgICAgICAgICAgIGlmIChyZXMub2JqZWN0KSB7XG4gICAgICAgICAgICAgICAgcmVzLm9iamVjdCA9IFBhcnNlLk9iamVjdC5mcm9tSlNPTihyZXMub2JqZWN0KTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBhd2FpdCBydW5UcmlnZ2VyKHRyaWdnZXIsIGBhZnRlckV2ZW50LiR7Y2xhc3NOYW1lfWAsIHJlcywgYXV0aCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAoIXJlcy5zZW5kRXZlbnQpIHtcbiAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKHJlcy5vYmplY3QgJiYgdHlwZW9mIHJlcy5vYmplY3QudG9KU09OID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICAgIGRlbGV0ZWRQYXJzZU9iamVjdCA9IHJlcy5vYmplY3QudG9KU09OKCk7XG4gICAgICAgICAgICAgIGRlbGV0ZWRQYXJzZU9iamVjdC5jbGFzc05hbWUgPSBjbGFzc05hbWU7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjbGllbnQucHVzaERlbGV0ZShyZXF1ZXN0SWQsIGRlbGV0ZWRQYXJzZU9iamVjdCk7XG4gICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgIENsaWVudC5wdXNoRXJyb3IoXG4gICAgICAgICAgICAgIGNsaWVudC5wYXJzZVdlYlNvY2tldCxcbiAgICAgICAgICAgICAgZXJyb3IuY29kZSB8fCAxNDEsXG4gICAgICAgICAgICAgIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsXG4gICAgICAgICAgICAgIGZhbHNlLFxuICAgICAgICAgICAgICByZXF1ZXN0SWRcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgICBsb2dnZXIuZXJyb3IoXG4gICAgICAgICAgICAgIGBGYWlsZWQgcnVubmluZyBhZnRlckxpdmVRdWVyeUV2ZW50IG9uIGNsYXNzICR7Y2xhc3NOYW1lfSBmb3IgZXZlbnQgJHtyZXMuZXZlbnR9IHdpdGggc2Vzc2lvbiAke3Jlcy5zZXNzaW9uVG9rZW59IHdpdGg6XFxuIEVycm9yOiBgICtcbiAgICAgICAgICAgICAgICBKU09OLnN0cmluZ2lmeShlcnJvcilcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvLyBNZXNzYWdlIGlzIHRoZSBKU09OIG9iamVjdCBmcm9tIHB1Ymxpc2hlciBhZnRlciBpbmZsYXRlZC4gTWVzc2FnZS5jdXJyZW50UGFyc2VPYmplY3QgaXMgdGhlIFBhcnNlT2JqZWN0IGFmdGVyIGNoYW5nZXMuXG4gIC8vIE1lc3NhZ2Uub3JpZ2luYWxQYXJzZU9iamVjdCBpcyB0aGUgb3JpZ2luYWwgUGFyc2VPYmplY3QuXG4gIGFzeW5jIF9vbkFmdGVyU2F2ZShtZXNzYWdlOiBhbnkpOiB2b2lkIHtcbiAgICBsb2dnZXIudmVyYm9zZShQYXJzZS5hcHBsaWNhdGlvbklkICsgJ2FmdGVyU2F2ZSBpcyB0cmlnZ2VyZWQnKTtcblxuICAgIGxldCBvcmlnaW5hbFBhcnNlT2JqZWN0ID0gbnVsbDtcbiAgICBpZiAobWVzc2FnZS5vcmlnaW5hbFBhcnNlT2JqZWN0KSB7XG4gICAgICBvcmlnaW5hbFBhcnNlT2JqZWN0ID0gbWVzc2FnZS5vcmlnaW5hbFBhcnNlT2JqZWN0LnRvSlNPTigpO1xuICAgIH1cbiAgICBjb25zdCBjbGFzc0xldmVsUGVybWlzc2lvbnMgPSBtZXNzYWdlLmNsYXNzTGV2ZWxQZXJtaXNzaW9ucztcbiAgICBsZXQgY3VycmVudFBhcnNlT2JqZWN0ID0gbWVzc2FnZS5jdXJyZW50UGFyc2VPYmplY3QudG9KU09OKCk7XG4gICAgY29uc3QgY2xhc3NOYW1lID0gY3VycmVudFBhcnNlT2JqZWN0LmNsYXNzTmFtZTtcbiAgICBsb2dnZXIudmVyYm9zZSgnQ2xhc3NOYW1lOiAlcyB8IE9iamVjdElkOiAlcycsIGNsYXNzTmFtZSwgY3VycmVudFBhcnNlT2JqZWN0LmlkKTtcbiAgICBsb2dnZXIudmVyYm9zZSgnQ3VycmVudCBjbGllbnQgbnVtYmVyIDogJWQnLCB0aGlzLmNsaWVudHMuc2l6ZSk7XG5cbiAgICBjb25zdCBjbGFzc1N1YnNjcmlwdGlvbnMgPSB0aGlzLnN1YnNjcmlwdGlvbnMuZ2V0KGNsYXNzTmFtZSk7XG4gICAgaWYgKHR5cGVvZiBjbGFzc1N1YnNjcmlwdGlvbnMgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICBsb2dnZXIuZGVidWcoJ0NhbiBub3QgZmluZCBzdWJzY3JpcHRpb25zIHVuZGVyIHRoaXMgY2xhc3MgJyArIGNsYXNzTmFtZSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGZvciAoY29uc3Qgc3Vic2NyaXB0aW9uIG9mIGNsYXNzU3Vic2NyaXB0aW9ucy52YWx1ZXMoKSkge1xuICAgICAgY29uc3QgaXNPcmlnaW5hbFN1YnNjcmlwdGlvbk1hdGNoZWQgPSB0aGlzLl9tYXRjaGVzU3Vic2NyaXB0aW9uKFxuICAgICAgICBvcmlnaW5hbFBhcnNlT2JqZWN0LFxuICAgICAgICBzdWJzY3JpcHRpb25cbiAgICAgICk7XG4gICAgICBjb25zdCBpc0N1cnJlbnRTdWJzY3JpcHRpb25NYXRjaGVkID0gdGhpcy5fbWF0Y2hlc1N1YnNjcmlwdGlvbihcbiAgICAgICAgY3VycmVudFBhcnNlT2JqZWN0LFxuICAgICAgICBzdWJzY3JpcHRpb25cbiAgICAgICk7XG4gICAgICBmb3IgKGNvbnN0IFtjbGllbnRJZCwgcmVxdWVzdElkc10gb2YgXy5lbnRyaWVzKHN1YnNjcmlwdGlvbi5jbGllbnRSZXF1ZXN0SWRzKSkge1xuICAgICAgICBjb25zdCBjbGllbnQgPSB0aGlzLmNsaWVudHMuZ2V0KGNsaWVudElkKTtcbiAgICAgICAgaWYgKHR5cGVvZiBjbGllbnQgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgICAgY29udGludWU7XG4gICAgICAgIH1cbiAgICAgICAgcmVxdWVzdElkcy5mb3JFYWNoKGFzeW5jIHJlcXVlc3RJZCA9PiB7XG4gICAgICAgICAgLy8gU2V0IG9yaWduYWwgUGFyc2VPYmplY3QgQUNMIGNoZWNraW5nIHByb21pc2UsIGlmIHRoZSBvYmplY3QgZG9lcyBub3QgbWF0Y2hcbiAgICAgICAgICAvLyBzdWJzY3JpcHRpb24sIHdlIGRvIG5vdCBuZWVkIHRvIGNoZWNrIEFDTFxuICAgICAgICAgIGxldCBvcmlnaW5hbEFDTENoZWNraW5nUHJvbWlzZTtcbiAgICAgICAgICBpZiAoIWlzT3JpZ2luYWxTdWJzY3JpcHRpb25NYXRjaGVkKSB7XG4gICAgICAgICAgICBvcmlnaW5hbEFDTENoZWNraW5nUHJvbWlzZSA9IFByb21pc2UucmVzb2x2ZShmYWxzZSk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGxldCBvcmlnaW5hbEFDTDtcbiAgICAgICAgICAgIGlmIChtZXNzYWdlLm9yaWdpbmFsUGFyc2VPYmplY3QpIHtcbiAgICAgICAgICAgICAgb3JpZ2luYWxBQ0wgPSBtZXNzYWdlLm9yaWdpbmFsUGFyc2VPYmplY3QuZ2V0QUNMKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBvcmlnaW5hbEFDTENoZWNraW5nUHJvbWlzZSA9IHRoaXMuX21hdGNoZXNBQ0wob3JpZ2luYWxBQ0wsIGNsaWVudCwgcmVxdWVzdElkKTtcbiAgICAgICAgICB9XG4gICAgICAgICAgLy8gU2V0IGN1cnJlbnQgUGFyc2VPYmplY3QgQUNMIGNoZWNraW5nIHByb21pc2UsIGlmIHRoZSBvYmplY3QgZG9lcyBub3QgbWF0Y2hcbiAgICAgICAgICAvLyBzdWJzY3JpcHRpb24sIHdlIGRvIG5vdCBuZWVkIHRvIGNoZWNrIEFDTFxuICAgICAgICAgIGxldCBjdXJyZW50QUNMQ2hlY2tpbmdQcm9taXNlO1xuICAgICAgICAgIGxldCByZXMgPSB7fTtcbiAgICAgICAgICBpZiAoIWlzQ3VycmVudFN1YnNjcmlwdGlvbk1hdGNoZWQpIHtcbiAgICAgICAgICAgIGN1cnJlbnRBQ0xDaGVja2luZ1Byb21pc2UgPSBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBjb25zdCBjdXJyZW50QUNMID0gbWVzc2FnZS5jdXJyZW50UGFyc2VPYmplY3QuZ2V0QUNMKCk7XG4gICAgICAgICAgICBjdXJyZW50QUNMQ2hlY2tpbmdQcm9taXNlID0gdGhpcy5fbWF0Y2hlc0FDTChjdXJyZW50QUNMLCBjbGllbnQsIHJlcXVlc3RJZCk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICBjb25zdCBvcCA9IHRoaXMuX2dldENMUE9wZXJhdGlvbihzdWJzY3JpcHRpb24ucXVlcnkpO1xuICAgICAgICAgICAgYXdhaXQgdGhpcy5fbWF0Y2hlc0NMUChcbiAgICAgICAgICAgICAgY2xhc3NMZXZlbFBlcm1pc3Npb25zLFxuICAgICAgICAgICAgICBtZXNzYWdlLmN1cnJlbnRQYXJzZU9iamVjdCxcbiAgICAgICAgICAgICAgY2xpZW50LFxuICAgICAgICAgICAgICByZXF1ZXN0SWQsXG4gICAgICAgICAgICAgIG9wXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgY29uc3QgW2lzT3JpZ2luYWxNYXRjaGVkLCBpc0N1cnJlbnRNYXRjaGVkXSA9IGF3YWl0IFByb21pc2UuYWxsKFtcbiAgICAgICAgICAgICAgb3JpZ2luYWxBQ0xDaGVja2luZ1Byb21pc2UsXG4gICAgICAgICAgICAgIGN1cnJlbnRBQ0xDaGVja2luZ1Byb21pc2UsXG4gICAgICAgICAgICBdKTtcbiAgICAgICAgICAgIGxvZ2dlci52ZXJib3NlKFxuICAgICAgICAgICAgICAnT3JpZ2luYWwgJWogfCBDdXJyZW50ICVqIHwgTWF0Y2g6ICVzLCAlcywgJXMsICVzIHwgUXVlcnk6ICVzJyxcbiAgICAgICAgICAgICAgb3JpZ2luYWxQYXJzZU9iamVjdCxcbiAgICAgICAgICAgICAgY3VycmVudFBhcnNlT2JqZWN0LFxuICAgICAgICAgICAgICBpc09yaWdpbmFsU3Vic2NyaXB0aW9uTWF0Y2hlZCxcbiAgICAgICAgICAgICAgaXNDdXJyZW50U3Vic2NyaXB0aW9uTWF0Y2hlZCxcbiAgICAgICAgICAgICAgaXNPcmlnaW5hbE1hdGNoZWQsXG4gICAgICAgICAgICAgIGlzQ3VycmVudE1hdGNoZWQsXG4gICAgICAgICAgICAgIHN1YnNjcmlwdGlvbi5oYXNoXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgLy8gRGVjaWRlIGV2ZW50IHR5cGVcbiAgICAgICAgICAgIGxldCB0eXBlO1xuICAgICAgICAgICAgaWYgKGlzT3JpZ2luYWxNYXRjaGVkICYmIGlzQ3VycmVudE1hdGNoZWQpIHtcbiAgICAgICAgICAgICAgdHlwZSA9ICd1cGRhdGUnO1xuICAgICAgICAgICAgfSBlbHNlIGlmIChpc09yaWdpbmFsTWF0Y2hlZCAmJiAhaXNDdXJyZW50TWF0Y2hlZCkge1xuICAgICAgICAgICAgICB0eXBlID0gJ2xlYXZlJztcbiAgICAgICAgICAgIH0gZWxzZSBpZiAoIWlzT3JpZ2luYWxNYXRjaGVkICYmIGlzQ3VycmVudE1hdGNoZWQpIHtcbiAgICAgICAgICAgICAgaWYgKG9yaWdpbmFsUGFyc2VPYmplY3QpIHtcbiAgICAgICAgICAgICAgICB0eXBlID0gJ2VudGVyJztcbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICB0eXBlID0gJ2NyZWF0ZSc7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmVzID0ge1xuICAgICAgICAgICAgICBldmVudDogdHlwZSxcbiAgICAgICAgICAgICAgc2Vzc2lvblRva2VuOiBjbGllbnQuc2Vzc2lvblRva2VuLFxuICAgICAgICAgICAgICBvYmplY3Q6IGN1cnJlbnRQYXJzZU9iamVjdCxcbiAgICAgICAgICAgICAgb3JpZ2luYWw6IG9yaWdpbmFsUGFyc2VPYmplY3QsXG4gICAgICAgICAgICAgIGNsaWVudHM6IHRoaXMuY2xpZW50cy5zaXplLFxuICAgICAgICAgICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICAgICAgICAgICAgdXNlTWFzdGVyS2V5OiBjbGllbnQuaGFzTWFzdGVyS2V5LFxuICAgICAgICAgICAgICBpbnN0YWxsYXRpb25JZDogY2xpZW50Lmluc3RhbGxhdGlvbklkLFxuICAgICAgICAgICAgICBzZW5kRXZlbnQ6IHRydWUsXG4gICAgICAgICAgICB9O1xuICAgICAgICAgICAgY29uc3QgdHJpZ2dlciA9IGdldFRyaWdnZXIoY2xhc3NOYW1lLCAnYWZ0ZXJFdmVudCcsIFBhcnNlLmFwcGxpY2F0aW9uSWQpO1xuICAgICAgICAgICAgaWYgKHRyaWdnZXIpIHtcbiAgICAgICAgICAgICAgaWYgKHJlcy5vYmplY3QpIHtcbiAgICAgICAgICAgICAgICByZXMub2JqZWN0ID0gUGFyc2UuT2JqZWN0LmZyb21KU09OKHJlcy5vYmplY3QpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGlmIChyZXMub3JpZ2luYWwpIHtcbiAgICAgICAgICAgICAgICByZXMub3JpZ2luYWwgPSBQYXJzZS5PYmplY3QuZnJvbUpTT04ocmVzLm9yaWdpbmFsKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBjb25zdCBhdXRoID0gYXdhaXQgdGhpcy5nZXRBdXRoRm9yU2Vzc2lvblRva2VuKHJlcy5zZXNzaW9uVG9rZW4pO1xuICAgICAgICAgICAgICByZXMudXNlciA9IGF1dGgudXNlcjtcbiAgICAgICAgICAgICAgYXdhaXQgcnVuVHJpZ2dlcih0cmlnZ2VyLCBgYWZ0ZXJFdmVudC4ke2NsYXNzTmFtZX1gLCByZXMsIGF1dGgpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKCFyZXMuc2VuZEV2ZW50KSB7XG4gICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChyZXMub2JqZWN0ICYmIHR5cGVvZiByZXMub2JqZWN0LnRvSlNPTiA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgICAgICBjdXJyZW50UGFyc2VPYmplY3QgPSByZXMub2JqZWN0LnRvSlNPTigpO1xuICAgICAgICAgICAgICBjdXJyZW50UGFyc2VPYmplY3QuY2xhc3NOYW1lID0gcmVzLm9iamVjdC5jbGFzc05hbWUgfHwgY2xhc3NOYW1lO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAocmVzLm9yaWdpbmFsICYmIHR5cGVvZiByZXMub3JpZ2luYWwudG9KU09OID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICAgIG9yaWdpbmFsUGFyc2VPYmplY3QgPSByZXMub3JpZ2luYWwudG9KU09OKCk7XG4gICAgICAgICAgICAgIG9yaWdpbmFsUGFyc2VPYmplY3QuY2xhc3NOYW1lID0gcmVzLm9yaWdpbmFsLmNsYXNzTmFtZSB8fCBjbGFzc05hbWU7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBjb25zdCBmdW5jdGlvbk5hbWUgPSAncHVzaCcgKyByZXMuZXZlbnQuY2hhckF0KDApLnRvVXBwZXJDYXNlKCkgKyByZXMuZXZlbnQuc2xpY2UoMSk7XG4gICAgICAgICAgICBpZiAoY2xpZW50W2Z1bmN0aW9uTmFtZV0pIHtcbiAgICAgICAgICAgICAgY2xpZW50W2Z1bmN0aW9uTmFtZV0ocmVxdWVzdElkLCBjdXJyZW50UGFyc2VPYmplY3QsIG9yaWdpbmFsUGFyc2VPYmplY3QpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgICBDbGllbnQucHVzaEVycm9yKFxuICAgICAgICAgICAgICBjbGllbnQucGFyc2VXZWJTb2NrZXQsXG4gICAgICAgICAgICAgIGVycm9yLmNvZGUgfHwgMTQxLFxuICAgICAgICAgICAgICBlcnJvci5tZXNzYWdlIHx8IGVycm9yLFxuICAgICAgICAgICAgICBmYWxzZSxcbiAgICAgICAgICAgICAgcmVxdWVzdElkXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgbG9nZ2VyLmVycm9yKFxuICAgICAgICAgICAgICBgRmFpbGVkIHJ1bm5pbmcgYWZ0ZXJMaXZlUXVlcnlFdmVudCBvbiBjbGFzcyAke2NsYXNzTmFtZX0gZm9yIGV2ZW50ICR7cmVzLmV2ZW50fSB3aXRoIHNlc3Npb24gJHtyZXMuc2Vzc2lvblRva2VufSB3aXRoOlxcbiBFcnJvcjogYCArXG4gICAgICAgICAgICAgICAgSlNPTi5zdHJpbmdpZnkoZXJyb3IpXG4gICAgICAgICAgICApO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgX29uQ29ubmVjdChwYXJzZVdlYnNvY2tldDogYW55KTogdm9pZCB7XG4gICAgcGFyc2VXZWJzb2NrZXQub24oJ21lc3NhZ2UnLCByZXF1ZXN0ID0+IHtcbiAgICAgIGlmICh0eXBlb2YgcmVxdWVzdCA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICByZXF1ZXN0ID0gSlNPTi5wYXJzZShyZXF1ZXN0KTtcbiAgICAgICAgfSBjYXRjaCAoZSkge1xuICAgICAgICAgIGxvZ2dlci5lcnJvcigndW5hYmxlIHRvIHBhcnNlIHJlcXVlc3QnLCByZXF1ZXN0LCBlKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGxvZ2dlci52ZXJib3NlKCdSZXF1ZXN0OiAlaicsIHJlcXVlc3QpO1xuXG4gICAgICAvLyBDaGVjayB3aGV0aGVyIHRoaXMgcmVxdWVzdCBpcyBhIHZhbGlkIHJlcXVlc3QsIHJldHVybiBlcnJvciBkaXJlY3RseSBpZiBub3RcbiAgICAgIGlmIChcbiAgICAgICAgIXR2NC52YWxpZGF0ZShyZXF1ZXN0LCBSZXF1ZXN0U2NoZW1hWydnZW5lcmFsJ10pIHx8XG4gICAgICAgICF0djQudmFsaWRhdGUocmVxdWVzdCwgUmVxdWVzdFNjaGVtYVtyZXF1ZXN0Lm9wXSlcbiAgICAgICkge1xuICAgICAgICBDbGllbnQucHVzaEVycm9yKHBhcnNlV2Vic29ja2V0LCAxLCB0djQuZXJyb3IubWVzc2FnZSk7XG4gICAgICAgIGxvZ2dlci5lcnJvcignQ29ubmVjdCBtZXNzYWdlIGVycm9yICVzJywgdHY0LmVycm9yLm1lc3NhZ2UpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIHN3aXRjaCAocmVxdWVzdC5vcCkge1xuICAgICAgICBjYXNlICdjb25uZWN0JzpcbiAgICAgICAgICB0aGlzLl9oYW5kbGVDb25uZWN0KHBhcnNlV2Vic29ja2V0LCByZXF1ZXN0KTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSAnc3Vic2NyaWJlJzpcbiAgICAgICAgICB0aGlzLl9oYW5kbGVTdWJzY3JpYmUocGFyc2VXZWJzb2NrZXQsIHJlcXVlc3QpO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlICd1cGRhdGUnOlxuICAgICAgICAgIHRoaXMuX2hhbmRsZVVwZGF0ZVN1YnNjcmlwdGlvbihwYXJzZVdlYnNvY2tldCwgcmVxdWVzdCk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgJ3Vuc3Vic2NyaWJlJzpcbiAgICAgICAgICB0aGlzLl9oYW5kbGVVbnN1YnNjcmliZShwYXJzZVdlYnNvY2tldCwgcmVxdWVzdCk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgQ2xpZW50LnB1c2hFcnJvcihwYXJzZVdlYnNvY2tldCwgMywgJ0dldCB1bmtub3duIG9wZXJhdGlvbicpO1xuICAgICAgICAgIGxvZ2dlci5lcnJvcignR2V0IHVua25vd24gb3BlcmF0aW9uJywgcmVxdWVzdC5vcCk7XG4gICAgICB9XG4gICAgfSk7XG5cbiAgICBwYXJzZVdlYnNvY2tldC5vbignZGlzY29ubmVjdCcsICgpID0+IHtcbiAgICAgIGxvZ2dlci5pbmZvKGBDbGllbnQgZGlzY29ubmVjdDogJHtwYXJzZVdlYnNvY2tldC5jbGllbnRJZH1gKTtcbiAgICAgIGNvbnN0IGNsaWVudElkID0gcGFyc2VXZWJzb2NrZXQuY2xpZW50SWQ7XG4gICAgICBpZiAoIXRoaXMuY2xpZW50cy5oYXMoY2xpZW50SWQpKSB7XG4gICAgICAgIHJ1bkxpdmVRdWVyeUV2ZW50SGFuZGxlcnMoe1xuICAgICAgICAgIGV2ZW50OiAnd3NfZGlzY29ubmVjdF9lcnJvcicsXG4gICAgICAgICAgY2xpZW50czogdGhpcy5jbGllbnRzLnNpemUsXG4gICAgICAgICAgc3Vic2NyaXB0aW9uczogdGhpcy5zdWJzY3JpcHRpb25zLnNpemUsXG4gICAgICAgICAgZXJyb3I6IGBVbmFibGUgdG8gZmluZCBjbGllbnQgJHtjbGllbnRJZH1gLFxuICAgICAgICB9KTtcbiAgICAgICAgbG9nZ2VyLmVycm9yKGBDYW4gbm90IGZpbmQgY2xpZW50ICR7Y2xpZW50SWR9IG9uIGRpc2Nvbm5lY3RgKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuXG4gICAgICAvLyBEZWxldGUgY2xpZW50XG4gICAgICBjb25zdCBjbGllbnQgPSB0aGlzLmNsaWVudHMuZ2V0KGNsaWVudElkKTtcbiAgICAgIHRoaXMuY2xpZW50cy5kZWxldGUoY2xpZW50SWQpO1xuXG4gICAgICAvLyBEZWxldGUgY2xpZW50IGZyb20gc3Vic2NyaXB0aW9uc1xuICAgICAgZm9yIChjb25zdCBbcmVxdWVzdElkLCBzdWJzY3JpcHRpb25JbmZvXSBvZiBfLmVudHJpZXMoY2xpZW50LnN1YnNjcmlwdGlvbkluZm9zKSkge1xuICAgICAgICBjb25zdCBzdWJzY3JpcHRpb24gPSBzdWJzY3JpcHRpb25JbmZvLnN1YnNjcmlwdGlvbjtcbiAgICAgICAgc3Vic2NyaXB0aW9uLmRlbGV0ZUNsaWVudFN1YnNjcmlwdGlvbihjbGllbnRJZCwgcmVxdWVzdElkKTtcblxuICAgICAgICAvLyBJZiB0aGVyZSBpcyBubyBjbGllbnQgd2hpY2ggaXMgc3Vic2NyaWJpbmcgdGhpcyBzdWJzY3JpcHRpb24sIHJlbW92ZSBpdCBmcm9tIHN1YnNjcmlwdGlvbnNcbiAgICAgICAgY29uc3QgY2xhc3NTdWJzY3JpcHRpb25zID0gdGhpcy5zdWJzY3JpcHRpb25zLmdldChzdWJzY3JpcHRpb24uY2xhc3NOYW1lKTtcbiAgICAgICAgaWYgKCFzdWJzY3JpcHRpb24uaGFzU3Vic2NyaWJpbmdDbGllbnQoKSkge1xuICAgICAgICAgIGNsYXNzU3Vic2NyaXB0aW9ucy5kZWxldGUoc3Vic2NyaXB0aW9uLmhhc2gpO1xuICAgICAgICB9XG4gICAgICAgIC8vIElmIHRoZXJlIGlzIG5vIHN1YnNjcmlwdGlvbnMgdW5kZXIgdGhpcyBjbGFzcywgcmVtb3ZlIGl0IGZyb20gc3Vic2NyaXB0aW9uc1xuICAgICAgICBpZiAoY2xhc3NTdWJzY3JpcHRpb25zLnNpemUgPT09IDApIHtcbiAgICAgICAgICB0aGlzLnN1YnNjcmlwdGlvbnMuZGVsZXRlKHN1YnNjcmlwdGlvbi5jbGFzc05hbWUpO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGxvZ2dlci52ZXJib3NlKCdDdXJyZW50IGNsaWVudHMgJWQnLCB0aGlzLmNsaWVudHMuc2l6ZSk7XG4gICAgICBsb2dnZXIudmVyYm9zZSgnQ3VycmVudCBzdWJzY3JpcHRpb25zICVkJywgdGhpcy5zdWJzY3JpcHRpb25zLnNpemUpO1xuICAgICAgcnVuTGl2ZVF1ZXJ5RXZlbnRIYW5kbGVycyh7XG4gICAgICAgIGV2ZW50OiAnd3NfZGlzY29ubmVjdCcsXG4gICAgICAgIGNsaWVudHM6IHRoaXMuY2xpZW50cy5zaXplLFxuICAgICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICAgICAgdXNlTWFzdGVyS2V5OiBjbGllbnQuaGFzTWFzdGVyS2V5LFxuICAgICAgICBpbnN0YWxsYXRpb25JZDogY2xpZW50Lmluc3RhbGxhdGlvbklkLFxuICAgICAgICBzZXNzaW9uVG9rZW46IGNsaWVudC5zZXNzaW9uVG9rZW4sXG4gICAgICB9KTtcbiAgICB9KTtcblxuICAgIHJ1bkxpdmVRdWVyeUV2ZW50SGFuZGxlcnMoe1xuICAgICAgZXZlbnQ6ICd3c19jb25uZWN0JyxcbiAgICAgIGNsaWVudHM6IHRoaXMuY2xpZW50cy5zaXplLFxuICAgICAgc3Vic2NyaXB0aW9uczogdGhpcy5zdWJzY3JpcHRpb25zLnNpemUsXG4gICAgfSk7XG4gIH1cblxuICBfbWF0Y2hlc1N1YnNjcmlwdGlvbihwYXJzZU9iamVjdDogYW55LCBzdWJzY3JpcHRpb246IGFueSk6IGJvb2xlYW4ge1xuICAgIC8vIE9iamVjdCBpcyB1bmRlZmluZWQgb3IgbnVsbCwgbm90IG1hdGNoXG4gICAgaWYgKCFwYXJzZU9iamVjdCkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgICByZXR1cm4gbWF0Y2hlc1F1ZXJ5KHBhcnNlT2JqZWN0LCBzdWJzY3JpcHRpb24ucXVlcnkpO1xuICB9XG5cbiAgZ2V0QXV0aEZvclNlc3Npb25Ub2tlbihzZXNzaW9uVG9rZW46ID9zdHJpbmcpOiBQcm9taXNlPHsgYXV0aDogP0F1dGgsIHVzZXJJZDogP3N0cmluZyB9PiB7XG4gICAgaWYgKCFzZXNzaW9uVG9rZW4pIHtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoe30pO1xuICAgIH1cbiAgICBjb25zdCBmcm9tQ2FjaGUgPSB0aGlzLmF1dGhDYWNoZS5nZXQoc2Vzc2lvblRva2VuKTtcbiAgICBpZiAoZnJvbUNhY2hlKSB7XG4gICAgICByZXR1cm4gZnJvbUNhY2hlO1xuICAgIH1cbiAgICBjb25zdCBhdXRoUHJvbWlzZSA9IGdldEF1dGhGb3JTZXNzaW9uVG9rZW4oe1xuICAgICAgY2FjaGVDb250cm9sbGVyOiB0aGlzLmNhY2hlQ29udHJvbGxlcixcbiAgICAgIHNlc3Npb25Ub2tlbjogc2Vzc2lvblRva2VuLFxuICAgIH0pXG4gICAgICAudGhlbihhdXRoID0+IHtcbiAgICAgICAgcmV0dXJuIHsgYXV0aCwgdXNlcklkOiBhdXRoICYmIGF1dGgudXNlciAmJiBhdXRoLnVzZXIuaWQgfTtcbiAgICAgIH0pXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xuICAgICAgICAvLyBUaGVyZSB3YXMgYW4gZXJyb3Igd2l0aCB0aGUgc2Vzc2lvbiB0b2tlblxuICAgICAgICBjb25zdCByZXN1bHQgPSB7fTtcbiAgICAgICAgaWYgKGVycm9yICYmIGVycm9yLmNvZGUgPT09IFBhcnNlLkVycm9yLklOVkFMSURfU0VTU0lPTl9UT0tFTikge1xuICAgICAgICAgIHJlc3VsdC5lcnJvciA9IGVycm9yO1xuICAgICAgICAgIHRoaXMuYXV0aENhY2hlLnNldChzZXNzaW9uVG9rZW4sIFByb21pc2UucmVzb2x2ZShyZXN1bHQpLCB0aGlzLmNvbmZpZy5jYWNoZVRpbWVvdXQpO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHRoaXMuYXV0aENhY2hlLmRlbChzZXNzaW9uVG9rZW4pO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICB9KTtcbiAgICB0aGlzLmF1dGhDYWNoZS5zZXQoc2Vzc2lvblRva2VuLCBhdXRoUHJvbWlzZSk7XG4gICAgcmV0dXJuIGF1dGhQcm9taXNlO1xuICB9XG5cbiAgYXN5bmMgX21hdGNoZXNDTFAoXG4gICAgY2xhc3NMZXZlbFBlcm1pc3Npb25zOiA/YW55LFxuICAgIG9iamVjdDogYW55LFxuICAgIGNsaWVudDogYW55LFxuICAgIHJlcXVlc3RJZDogbnVtYmVyLFxuICAgIG9wOiBzdHJpbmdcbiAgKTogYW55IHtcbiAgICAvLyB0cnkgdG8gbWF0Y2ggb24gdXNlciBmaXJzdCwgbGVzcyBleHBlbnNpdmUgdGhhbiB3aXRoIHJvbGVzXG4gICAgY29uc3Qgc3Vic2NyaXB0aW9uSW5mbyA9IGNsaWVudC5nZXRTdWJzY3JpcHRpb25JbmZvKHJlcXVlc3RJZCk7XG4gICAgY29uc3QgYWNsR3JvdXAgPSBbJyonXTtcbiAgICBsZXQgdXNlcklkO1xuICAgIGlmICh0eXBlb2Ygc3Vic2NyaXB0aW9uSW5mbyAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIGNvbnN0IHsgdXNlcklkIH0gPSBhd2FpdCB0aGlzLmdldEF1dGhGb3JTZXNzaW9uVG9rZW4oc3Vic2NyaXB0aW9uSW5mby5zZXNzaW9uVG9rZW4pO1xuICAgICAgaWYgKHVzZXJJZCkge1xuICAgICAgICBhY2xHcm91cC5wdXNoKHVzZXJJZCk7XG4gICAgICB9XG4gICAgfVxuICAgIHRyeSB7XG4gICAgICBhd2FpdCBTY2hlbWFDb250cm9sbGVyLnZhbGlkYXRlUGVybWlzc2lvbihcbiAgICAgICAgY2xhc3NMZXZlbFBlcm1pc3Npb25zLFxuICAgICAgICBvYmplY3QuY2xhc3NOYW1lLFxuICAgICAgICBhY2xHcm91cCxcbiAgICAgICAgb3BcbiAgICAgICk7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICBsb2dnZXIudmVyYm9zZShgRmFpbGVkIG1hdGNoaW5nIENMUCBmb3IgJHtvYmplY3QuaWR9ICR7dXNlcklkfSAke2V9YCk7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIC8vIFRPRE86IGhhbmRsZSByb2xlcyBwZXJtaXNzaW9uc1xuICAgIC8vIE9iamVjdC5rZXlzKGNsYXNzTGV2ZWxQZXJtaXNzaW9ucykuZm9yRWFjaCgoa2V5KSA9PiB7XG4gICAgLy8gICBjb25zdCBwZXJtID0gY2xhc3NMZXZlbFBlcm1pc3Npb25zW2tleV07XG4gICAgLy8gICBPYmplY3Qua2V5cyhwZXJtKS5mb3JFYWNoKChrZXkpID0+IHtcbiAgICAvLyAgICAgaWYgKGtleS5pbmRleE9mKCdyb2xlJykpXG4gICAgLy8gICB9KTtcbiAgICAvLyB9KVxuICAgIC8vIC8vIGl0J3MgcmVqZWN0ZWQgaGVyZSwgY2hlY2sgdGhlIHJvbGVzXG4gICAgLy8gdmFyIHJvbGVzUXVlcnkgPSBuZXcgUGFyc2UuUXVlcnkoUGFyc2UuUm9sZSk7XG4gICAgLy8gcm9sZXNRdWVyeS5lcXVhbFRvKFwidXNlcnNcIiwgdXNlcik7XG4gICAgLy8gcmV0dXJuIHJvbGVzUXVlcnkuZmluZCh7dXNlTWFzdGVyS2V5OnRydWV9KTtcbiAgfVxuXG4gIF9nZXRDTFBPcGVyYXRpb24ocXVlcnk6IGFueSkge1xuICAgIHJldHVybiB0eXBlb2YgcXVlcnkgPT09ICdvYmplY3QnICYmXG4gICAgICBPYmplY3Qua2V5cyhxdWVyeSkubGVuZ3RoID09IDEgJiZcbiAgICAgIHR5cGVvZiBxdWVyeS5vYmplY3RJZCA9PT0gJ3N0cmluZydcbiAgICAgID8gJ2dldCdcbiAgICAgIDogJ2ZpbmQnO1xuICB9XG5cbiAgYXN5bmMgX3ZlcmlmeUFDTChhY2w6IGFueSwgdG9rZW46IHN0cmluZykge1xuICAgIGlmICghdG9rZW4pIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICBjb25zdCB7IGF1dGgsIHVzZXJJZCB9ID0gYXdhaXQgdGhpcy5nZXRBdXRoRm9yU2Vzc2lvblRva2VuKHRva2VuKTtcblxuICAgIC8vIEdldHRpbmcgdGhlIHNlc3Npb24gdG9rZW4gZmFpbGVkXG4gICAgLy8gVGhpcyBtZWFucyB0aGF0IG5vIGFkZGl0aW9uYWwgYXV0aCBpcyBhdmFpbGFibGVcbiAgICAvLyBBdCB0aGlzIHBvaW50LCBqdXN0IGJhaWwgb3V0IGFzIG5vIGFkZGl0aW9uYWwgdmlzaWJpbGl0eSBjYW4gYmUgaW5mZXJyZWQuXG4gICAgaWYgKCFhdXRoIHx8ICF1c2VySWQpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgY29uc3QgaXNTdWJzY3JpcHRpb25TZXNzaW9uVG9rZW5NYXRjaGVkID0gYWNsLmdldFJlYWRBY2Nlc3ModXNlcklkKTtcbiAgICBpZiAoaXNTdWJzY3JpcHRpb25TZXNzaW9uVG9rZW5NYXRjaGVkKSB7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9XG5cbiAgICAvLyBDaGVjayBpZiB0aGUgdXNlciBoYXMgYW55IHJvbGVzIHRoYXQgbWF0Y2ggdGhlIEFDTFxuICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKVxuICAgICAgLnRoZW4oYXN5bmMgKCkgPT4ge1xuICAgICAgICAvLyBSZXNvbHZlIGZhbHNlIHJpZ2h0IGF3YXkgaWYgdGhlIGFjbCBkb2Vzbid0IGhhdmUgYW55IHJvbGVzXG4gICAgICAgIGNvbnN0IGFjbF9oYXNfcm9sZXMgPSBPYmplY3Qua2V5cyhhY2wucGVybWlzc2lvbnNCeUlkKS5zb21lKGtleSA9PiBrZXkuc3RhcnRzV2l0aCgncm9sZTonKSk7XG4gICAgICAgIGlmICghYWNsX2hhc19yb2xlcykge1xuICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGNvbnN0IHJvbGVOYW1lcyA9IGF3YWl0IGF1dGguZ2V0VXNlclJvbGVzKCk7XG4gICAgICAgIC8vIEZpbmFsbHksIHNlZSBpZiBhbnkgb2YgdGhlIHVzZXIncyByb2xlcyBhbGxvdyB0aGVtIHJlYWQgYWNjZXNzXG4gICAgICAgIGZvciAoY29uc3Qgcm9sZSBvZiByb2xlTmFtZXMpIHtcbiAgICAgICAgICAvLyBXZSB1c2UgZ2V0UmVhZEFjY2VzcyBhcyBgcm9sZWAgaXMgaW4gdGhlIGZvcm0gYHJvbGU6cm9sZU5hbWVgXG4gICAgICAgICAgaWYgKGFjbC5nZXRSZWFkQWNjZXNzKHJvbGUpKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfSlcbiAgICAgIC5jYXRjaCgoKSA9PiB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH0pO1xuICB9XG5cbiAgYXN5bmMgX21hdGNoZXNBQ0woYWNsOiBhbnksIGNsaWVudDogYW55LCByZXF1ZXN0SWQ6IG51bWJlcik6IFByb21pc2U8Ym9vbGVhbj4ge1xuICAgIC8vIFJldHVybiB0cnVlIGRpcmVjdGx5IGlmIEFDTCBpc24ndCBwcmVzZW50LCBBQ0wgaXMgcHVibGljIHJlYWQsIG9yIGNsaWVudCBoYXMgbWFzdGVyIGtleVxuICAgIGlmICghYWNsIHx8IGFjbC5nZXRQdWJsaWNSZWFkQWNjZXNzKCkgfHwgY2xpZW50Lmhhc01hc3RlcktleSkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIC8vIENoZWNrIHN1YnNjcmlwdGlvbiBzZXNzaW9uVG9rZW4gbWF0Y2hlcyBBQ0wgZmlyc3RcbiAgICBjb25zdCBzdWJzY3JpcHRpb25JbmZvID0gY2xpZW50LmdldFN1YnNjcmlwdGlvbkluZm8ocmVxdWVzdElkKTtcbiAgICBpZiAodHlwZW9mIHN1YnNjcmlwdGlvbkluZm8gPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgY29uc3Qgc3Vic2NyaXB0aW9uVG9rZW4gPSBzdWJzY3JpcHRpb25JbmZvLnNlc3Npb25Ub2tlbjtcbiAgICBjb25zdCBjbGllbnRTZXNzaW9uVG9rZW4gPSBjbGllbnQuc2Vzc2lvblRva2VuO1xuXG4gICAgaWYgKGF3YWl0IHRoaXMuX3ZlcmlmeUFDTChhY2wsIHN1YnNjcmlwdGlvblRva2VuKSkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuXG4gICAgaWYgKGF3YWl0IHRoaXMuX3ZlcmlmeUFDTChhY2wsIGNsaWVudFNlc3Npb25Ub2tlbikpIHtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cblxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIGFzeW5jIF9oYW5kbGVDb25uZWN0KHBhcnNlV2Vic29ja2V0OiBhbnksIHJlcXVlc3Q6IGFueSk6IGFueSB7XG4gICAgaWYgKCF0aGlzLl92YWxpZGF0ZUtleXMocmVxdWVzdCwgdGhpcy5rZXlQYWlycykpIHtcbiAgICAgIENsaWVudC5wdXNoRXJyb3IocGFyc2VXZWJzb2NrZXQsIDQsICdLZXkgaW4gcmVxdWVzdCBpcyBub3QgdmFsaWQnKTtcbiAgICAgIGxvZ2dlci5lcnJvcignS2V5IGluIHJlcXVlc3QgaXMgbm90IHZhbGlkJyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGNvbnN0IGhhc01hc3RlcktleSA9IHRoaXMuX2hhc01hc3RlcktleShyZXF1ZXN0LCB0aGlzLmtleVBhaXJzKTtcbiAgICBjb25zdCBjbGllbnRJZCA9IHV1aWR2NCgpO1xuICAgIGNvbnN0IGNsaWVudCA9IG5ldyBDbGllbnQoXG4gICAgICBjbGllbnRJZCxcbiAgICAgIHBhcnNlV2Vic29ja2V0LFxuICAgICAgaGFzTWFzdGVyS2V5LFxuICAgICAgcmVxdWVzdC5zZXNzaW9uVG9rZW4sXG4gICAgICByZXF1ZXN0Lmluc3RhbGxhdGlvbklkXG4gICAgKTtcbiAgICB0cnkge1xuICAgICAgY29uc3QgcmVxID0ge1xuICAgICAgICBjbGllbnQsXG4gICAgICAgIGV2ZW50OiAnY29ubmVjdCcsXG4gICAgICAgIGNsaWVudHM6IHRoaXMuY2xpZW50cy5zaXplLFxuICAgICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICAgICAgc2Vzc2lvblRva2VuOiByZXF1ZXN0LnNlc3Npb25Ub2tlbixcbiAgICAgICAgdXNlTWFzdGVyS2V5OiBjbGllbnQuaGFzTWFzdGVyS2V5LFxuICAgICAgICBpbnN0YWxsYXRpb25JZDogcmVxdWVzdC5pbnN0YWxsYXRpb25JZCxcbiAgICAgIH07XG4gICAgICBjb25zdCB0cmlnZ2VyID0gZ2V0VHJpZ2dlcignQENvbm5lY3QnLCAnYmVmb3JlQ29ubmVjdCcsIFBhcnNlLmFwcGxpY2F0aW9uSWQpO1xuICAgICAgaWYgKHRyaWdnZXIpIHtcbiAgICAgICAgY29uc3QgYXV0aCA9IGF3YWl0IHRoaXMuZ2V0QXV0aEZvclNlc3Npb25Ub2tlbihyZXEuc2Vzc2lvblRva2VuKTtcbiAgICAgICAgcmVxLnVzZXIgPSBhdXRoLnVzZXI7XG4gICAgICAgIGF3YWl0IHJ1blRyaWdnZXIodHJpZ2dlciwgYGJlZm9yZUNvbm5lY3QuQENvbm5lY3RgLCByZXEsIGF1dGgpO1xuICAgICAgfVxuICAgICAgcGFyc2VXZWJzb2NrZXQuY2xpZW50SWQgPSBjbGllbnRJZDtcbiAgICAgIHRoaXMuY2xpZW50cy5zZXQocGFyc2VXZWJzb2NrZXQuY2xpZW50SWQsIGNsaWVudCk7XG4gICAgICBsb2dnZXIuaW5mbyhgQ3JlYXRlIG5ldyBjbGllbnQ6ICR7cGFyc2VXZWJzb2NrZXQuY2xpZW50SWR9YCk7XG4gICAgICBjbGllbnQucHVzaENvbm5lY3QoKTtcbiAgICAgIHJ1bkxpdmVRdWVyeUV2ZW50SGFuZGxlcnMocmVxKTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgQ2xpZW50LnB1c2hFcnJvcihwYXJzZVdlYnNvY2tldCwgZXJyb3IuY29kZSB8fCAxNDEsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIGZhbHNlKTtcbiAgICAgIGxvZ2dlci5lcnJvcihcbiAgICAgICAgYEZhaWxlZCBydW5uaW5nIGJlZm9yZUNvbm5lY3QgZm9yIHNlc3Npb24gJHtyZXF1ZXN0LnNlc3Npb25Ub2tlbn0gd2l0aDpcXG4gRXJyb3I6IGAgK1xuICAgICAgICAgIEpTT04uc3RyaW5naWZ5KGVycm9yKVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICBfaGFzTWFzdGVyS2V5KHJlcXVlc3Q6IGFueSwgdmFsaWRLZXlQYWlyczogYW55KTogYm9vbGVhbiB7XG4gICAgaWYgKCF2YWxpZEtleVBhaXJzIHx8IHZhbGlkS2V5UGFpcnMuc2l6ZSA9PSAwIHx8ICF2YWxpZEtleVBhaXJzLmhhcygnbWFzdGVyS2V5JykpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgaWYgKCFyZXF1ZXN0IHx8ICFPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocmVxdWVzdCwgJ21hc3RlcktleScpKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIHJldHVybiByZXF1ZXN0Lm1hc3RlcktleSA9PT0gdmFsaWRLZXlQYWlycy5nZXQoJ21hc3RlcktleScpO1xuICB9XG5cbiAgX3ZhbGlkYXRlS2V5cyhyZXF1ZXN0OiBhbnksIHZhbGlkS2V5UGFpcnM6IGFueSk6IGJvb2xlYW4ge1xuICAgIGlmICghdmFsaWRLZXlQYWlycyB8fCB2YWxpZEtleVBhaXJzLnNpemUgPT0gMCkge1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfVxuICAgIGxldCBpc1ZhbGlkID0gZmFsc2U7XG4gICAgZm9yIChjb25zdCBba2V5LCBzZWNyZXRdIG9mIHZhbGlkS2V5UGFpcnMpIHtcbiAgICAgIGlmICghcmVxdWVzdFtrZXldIHx8IHJlcXVlc3Rba2V5XSAhPT0gc2VjcmV0KSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgaXNWYWxpZCA9IHRydWU7XG4gICAgICBicmVhaztcbiAgICB9XG4gICAgcmV0dXJuIGlzVmFsaWQ7XG4gIH1cblxuICBhc3luYyBfaGFuZGxlU3Vic2NyaWJlKHBhcnNlV2Vic29ja2V0OiBhbnksIHJlcXVlc3Q6IGFueSk6IGFueSB7XG4gICAgLy8gSWYgd2UgY2FuIG5vdCBmaW5kIHRoaXMgY2xpZW50LCByZXR1cm4gZXJyb3IgdG8gY2xpZW50XG4gICAgaWYgKCFPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocGFyc2VXZWJzb2NrZXQsICdjbGllbnRJZCcpKSB7XG4gICAgICBDbGllbnQucHVzaEVycm9yKFxuICAgICAgICBwYXJzZVdlYnNvY2tldCxcbiAgICAgICAgMixcbiAgICAgICAgJ0NhbiBub3QgZmluZCB0aGlzIGNsaWVudCwgbWFrZSBzdXJlIHlvdSBjb25uZWN0IHRvIHNlcnZlciBiZWZvcmUgc3Vic2NyaWJpbmcnXG4gICAgICApO1xuICAgICAgbG9nZ2VyLmVycm9yKCdDYW4gbm90IGZpbmQgdGhpcyBjbGllbnQsIG1ha2Ugc3VyZSB5b3UgY29ubmVjdCB0byBzZXJ2ZXIgYmVmb3JlIHN1YnNjcmliaW5nJyk7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGNvbnN0IGNsaWVudCA9IHRoaXMuY2xpZW50cy5nZXQocGFyc2VXZWJzb2NrZXQuY2xpZW50SWQpO1xuICAgIGNvbnN0IGNsYXNzTmFtZSA9IHJlcXVlc3QucXVlcnkuY2xhc3NOYW1lO1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB0cmlnZ2VyID0gZ2V0VHJpZ2dlcihjbGFzc05hbWUsICdiZWZvcmVTdWJzY3JpYmUnLCBQYXJzZS5hcHBsaWNhdGlvbklkKTtcbiAgICAgIGlmICh0cmlnZ2VyKSB7XG4gICAgICAgIGNvbnN0IGF1dGggPSBhd2FpdCB0aGlzLmdldEF1dGhGb3JTZXNzaW9uVG9rZW4ocmVxdWVzdC5zZXNzaW9uVG9rZW4pO1xuICAgICAgICByZXF1ZXN0LnVzZXIgPSBhdXRoLnVzZXI7XG5cbiAgICAgICAgY29uc3QgcGFyc2VRdWVyeSA9IG5ldyBQYXJzZS5RdWVyeShjbGFzc05hbWUpO1xuICAgICAgICBwYXJzZVF1ZXJ5LndpdGhKU09OKHJlcXVlc3QucXVlcnkpO1xuICAgICAgICByZXF1ZXN0LnF1ZXJ5ID0gcGFyc2VRdWVyeTtcbiAgICAgICAgYXdhaXQgcnVuVHJpZ2dlcih0cmlnZ2VyLCBgYmVmb3JlU3Vic2NyaWJlLiR7Y2xhc3NOYW1lfWAsIHJlcXVlc3QsIGF1dGgpO1xuXG4gICAgICAgIGNvbnN0IHF1ZXJ5ID0gcmVxdWVzdC5xdWVyeS50b0pTT04oKTtcbiAgICAgICAgaWYgKHF1ZXJ5LmtleXMpIHtcbiAgICAgICAgICBxdWVyeS5maWVsZHMgPSBxdWVyeS5rZXlzLnNwbGl0KCcsJyk7XG4gICAgICAgIH1cbiAgICAgICAgcmVxdWVzdC5xdWVyeSA9IHF1ZXJ5O1xuICAgICAgfVxuXG4gICAgICAvLyBHZXQgc3Vic2NyaXB0aW9uIGZyb20gc3Vic2NyaXB0aW9ucywgY3JlYXRlIG9uZSBpZiBuZWNlc3NhcnlcbiAgICAgIGNvbnN0IHN1YnNjcmlwdGlvbkhhc2ggPSBxdWVyeUhhc2gocmVxdWVzdC5xdWVyeSk7XG4gICAgICAvLyBBZGQgY2xhc3NOYW1lIHRvIHN1YnNjcmlwdGlvbnMgaWYgbmVjZXNzYXJ5XG5cbiAgICAgIGlmICghdGhpcy5zdWJzY3JpcHRpb25zLmhhcyhjbGFzc05hbWUpKSB7XG4gICAgICAgIHRoaXMuc3Vic2NyaXB0aW9ucy5zZXQoY2xhc3NOYW1lLCBuZXcgTWFwKCkpO1xuICAgICAgfVxuICAgICAgY29uc3QgY2xhc3NTdWJzY3JpcHRpb25zID0gdGhpcy5zdWJzY3JpcHRpb25zLmdldChjbGFzc05hbWUpO1xuICAgICAgbGV0IHN1YnNjcmlwdGlvbjtcbiAgICAgIGlmIChjbGFzc1N1YnNjcmlwdGlvbnMuaGFzKHN1YnNjcmlwdGlvbkhhc2gpKSB7XG4gICAgICAgIHN1YnNjcmlwdGlvbiA9IGNsYXNzU3Vic2NyaXB0aW9ucy5nZXQoc3Vic2NyaXB0aW9uSGFzaCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBzdWJzY3JpcHRpb24gPSBuZXcgU3Vic2NyaXB0aW9uKGNsYXNzTmFtZSwgcmVxdWVzdC5xdWVyeS53aGVyZSwgc3Vic2NyaXB0aW9uSGFzaCk7XG4gICAgICAgIGNsYXNzU3Vic2NyaXB0aW9ucy5zZXQoc3Vic2NyaXB0aW9uSGFzaCwgc3Vic2NyaXB0aW9uKTtcbiAgICAgIH1cblxuICAgICAgLy8gQWRkIHN1YnNjcmlwdGlvbkluZm8gdG8gY2xpZW50XG4gICAgICBjb25zdCBzdWJzY3JpcHRpb25JbmZvID0ge1xuICAgICAgICBzdWJzY3JpcHRpb246IHN1YnNjcmlwdGlvbixcbiAgICAgIH07XG4gICAgICAvLyBBZGQgc2VsZWN0ZWQgZmllbGRzLCBzZXNzaW9uVG9rZW4gYW5kIGluc3RhbGxhdGlvbklkIGZvciB0aGlzIHN1YnNjcmlwdGlvbiBpZiBuZWNlc3NhcnlcbiAgICAgIGlmIChyZXF1ZXN0LnF1ZXJ5LmZpZWxkcykge1xuICAgICAgICBzdWJzY3JpcHRpb25JbmZvLmZpZWxkcyA9IHJlcXVlc3QucXVlcnkuZmllbGRzO1xuICAgICAgfVxuICAgICAgaWYgKHJlcXVlc3Quc2Vzc2lvblRva2VuKSB7XG4gICAgICAgIHN1YnNjcmlwdGlvbkluZm8uc2Vzc2lvblRva2VuID0gcmVxdWVzdC5zZXNzaW9uVG9rZW47XG4gICAgICB9XG4gICAgICBjbGllbnQuYWRkU3Vic2NyaXB0aW9uSW5mbyhyZXF1ZXN0LnJlcXVlc3RJZCwgc3Vic2NyaXB0aW9uSW5mbyk7XG5cbiAgICAgIC8vIEFkZCBjbGllbnRJZCB0byBzdWJzY3JpcHRpb25cbiAgICAgIHN1YnNjcmlwdGlvbi5hZGRDbGllbnRTdWJzY3JpcHRpb24ocGFyc2VXZWJzb2NrZXQuY2xpZW50SWQsIHJlcXVlc3QucmVxdWVzdElkKTtcblxuICAgICAgY2xpZW50LnB1c2hTdWJzY3JpYmUocmVxdWVzdC5yZXF1ZXN0SWQpO1xuXG4gICAgICBsb2dnZXIudmVyYm9zZShcbiAgICAgICAgYENyZWF0ZSBjbGllbnQgJHtwYXJzZVdlYnNvY2tldC5jbGllbnRJZH0gbmV3IHN1YnNjcmlwdGlvbjogJHtyZXF1ZXN0LnJlcXVlc3RJZH1gXG4gICAgICApO1xuICAgICAgbG9nZ2VyLnZlcmJvc2UoJ0N1cnJlbnQgY2xpZW50IG51bWJlcjogJWQnLCB0aGlzLmNsaWVudHMuc2l6ZSk7XG4gICAgICBydW5MaXZlUXVlcnlFdmVudEhhbmRsZXJzKHtcbiAgICAgICAgY2xpZW50LFxuICAgICAgICBldmVudDogJ3N1YnNjcmliZScsXG4gICAgICAgIGNsaWVudHM6IHRoaXMuY2xpZW50cy5zaXplLFxuICAgICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICAgICAgc2Vzc2lvblRva2VuOiByZXF1ZXN0LnNlc3Npb25Ub2tlbixcbiAgICAgICAgdXNlTWFzdGVyS2V5OiBjbGllbnQuaGFzTWFzdGVyS2V5LFxuICAgICAgICBpbnN0YWxsYXRpb25JZDogY2xpZW50Lmluc3RhbGxhdGlvbklkLFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgQ2xpZW50LnB1c2hFcnJvcihwYXJzZVdlYnNvY2tldCwgZS5jb2RlIHx8IDE0MSwgZS5tZXNzYWdlIHx8IGUsIGZhbHNlLCByZXF1ZXN0LnJlcXVlc3RJZCk7XG4gICAgICBsb2dnZXIuZXJyb3IoXG4gICAgICAgIGBGYWlsZWQgcnVubmluZyBiZWZvcmVTdWJzY3JpYmUgb24gJHtjbGFzc05hbWV9IGZvciBzZXNzaW9uICR7cmVxdWVzdC5zZXNzaW9uVG9rZW59IHdpdGg6XFxuIEVycm9yOiBgICtcbiAgICAgICAgICBKU09OLnN0cmluZ2lmeShlKVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICBfaGFuZGxlVXBkYXRlU3Vic2NyaXB0aW9uKHBhcnNlV2Vic29ja2V0OiBhbnksIHJlcXVlc3Q6IGFueSk6IGFueSB7XG4gICAgdGhpcy5faGFuZGxlVW5zdWJzY3JpYmUocGFyc2VXZWJzb2NrZXQsIHJlcXVlc3QsIGZhbHNlKTtcbiAgICB0aGlzLl9oYW5kbGVTdWJzY3JpYmUocGFyc2VXZWJzb2NrZXQsIHJlcXVlc3QpO1xuICB9XG5cbiAgX2hhbmRsZVVuc3Vic2NyaWJlKHBhcnNlV2Vic29ja2V0OiBhbnksIHJlcXVlc3Q6IGFueSwgbm90aWZ5Q2xpZW50OiBib29sZWFuID0gdHJ1ZSk6IGFueSB7XG4gICAgLy8gSWYgd2UgY2FuIG5vdCBmaW5kIHRoaXMgY2xpZW50LCByZXR1cm4gZXJyb3IgdG8gY2xpZW50XG4gICAgaWYgKCFPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwocGFyc2VXZWJzb2NrZXQsICdjbGllbnRJZCcpKSB7XG4gICAgICBDbGllbnQucHVzaEVycm9yKFxuICAgICAgICBwYXJzZVdlYnNvY2tldCxcbiAgICAgICAgMixcbiAgICAgICAgJ0NhbiBub3QgZmluZCB0aGlzIGNsaWVudCwgbWFrZSBzdXJlIHlvdSBjb25uZWN0IHRvIHNlcnZlciBiZWZvcmUgdW5zdWJzY3JpYmluZydcbiAgICAgICk7XG4gICAgICBsb2dnZXIuZXJyb3IoXG4gICAgICAgICdDYW4gbm90IGZpbmQgdGhpcyBjbGllbnQsIG1ha2Ugc3VyZSB5b3UgY29ubmVjdCB0byBzZXJ2ZXIgYmVmb3JlIHVuc3Vic2NyaWJpbmcnXG4gICAgICApO1xuICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICBjb25zdCByZXF1ZXN0SWQgPSByZXF1ZXN0LnJlcXVlc3RJZDtcbiAgICBjb25zdCBjbGllbnQgPSB0aGlzLmNsaWVudHMuZ2V0KHBhcnNlV2Vic29ja2V0LmNsaWVudElkKTtcbiAgICBpZiAodHlwZW9mIGNsaWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIENsaWVudC5wdXNoRXJyb3IoXG4gICAgICAgIHBhcnNlV2Vic29ja2V0LFxuICAgICAgICAyLFxuICAgICAgICAnQ2Fubm90IGZpbmQgY2xpZW50IHdpdGggY2xpZW50SWQgJyArXG4gICAgICAgICAgcGFyc2VXZWJzb2NrZXQuY2xpZW50SWQgK1xuICAgICAgICAgICcuIE1ha2Ugc3VyZSB5b3UgY29ubmVjdCB0byBsaXZlIHF1ZXJ5IHNlcnZlciBiZWZvcmUgdW5zdWJzY3JpYmluZy4nXG4gICAgICApO1xuICAgICAgbG9nZ2VyLmVycm9yKCdDYW4gbm90IGZpbmQgdGhpcyBjbGllbnQgJyArIHBhcnNlV2Vic29ja2V0LmNsaWVudElkKTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBzdWJzY3JpcHRpb25JbmZvID0gY2xpZW50LmdldFN1YnNjcmlwdGlvbkluZm8ocmVxdWVzdElkKTtcbiAgICBpZiAodHlwZW9mIHN1YnNjcmlwdGlvbkluZm8gPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICBDbGllbnQucHVzaEVycm9yKFxuICAgICAgICBwYXJzZVdlYnNvY2tldCxcbiAgICAgICAgMixcbiAgICAgICAgJ0Nhbm5vdCBmaW5kIHN1YnNjcmlwdGlvbiB3aXRoIGNsaWVudElkICcgK1xuICAgICAgICAgIHBhcnNlV2Vic29ja2V0LmNsaWVudElkICtcbiAgICAgICAgICAnIHN1YnNjcmlwdGlvbklkICcgK1xuICAgICAgICAgIHJlcXVlc3RJZCArXG4gICAgICAgICAgJy4gTWFrZSBzdXJlIHlvdSBzdWJzY3JpYmUgdG8gbGl2ZSBxdWVyeSBzZXJ2ZXIgYmVmb3JlIHVuc3Vic2NyaWJpbmcuJ1xuICAgICAgKTtcbiAgICAgIGxvZ2dlci5lcnJvcihcbiAgICAgICAgJ0NhbiBub3QgZmluZCBzdWJzY3JpcHRpb24gd2l0aCBjbGllbnRJZCAnICtcbiAgICAgICAgICBwYXJzZVdlYnNvY2tldC5jbGllbnRJZCArXG4gICAgICAgICAgJyBzdWJzY3JpcHRpb25JZCAnICtcbiAgICAgICAgICByZXF1ZXN0SWRcbiAgICAgICk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gUmVtb3ZlIHN1YnNjcmlwdGlvbiBmcm9tIGNsaWVudFxuICAgIGNsaWVudC5kZWxldGVTdWJzY3JpcHRpb25JbmZvKHJlcXVlc3RJZCk7XG4gICAgLy8gUmVtb3ZlIGNsaWVudCBmcm9tIHN1YnNjcmlwdGlvblxuICAgIGNvbnN0IHN1YnNjcmlwdGlvbiA9IHN1YnNjcmlwdGlvbkluZm8uc3Vic2NyaXB0aW9uO1xuICAgIGNvbnN0IGNsYXNzTmFtZSA9IHN1YnNjcmlwdGlvbi5jbGFzc05hbWU7XG4gICAgc3Vic2NyaXB0aW9uLmRlbGV0ZUNsaWVudFN1YnNjcmlwdGlvbihwYXJzZVdlYnNvY2tldC5jbGllbnRJZCwgcmVxdWVzdElkKTtcbiAgICAvLyBJZiB0aGVyZSBpcyBubyBjbGllbnQgd2hpY2ggaXMgc3Vic2NyaWJpbmcgdGhpcyBzdWJzY3JpcHRpb24sIHJlbW92ZSBpdCBmcm9tIHN1YnNjcmlwdGlvbnNcbiAgICBjb25zdCBjbGFzc1N1YnNjcmlwdGlvbnMgPSB0aGlzLnN1YnNjcmlwdGlvbnMuZ2V0KGNsYXNzTmFtZSk7XG4gICAgaWYgKCFzdWJzY3JpcHRpb24uaGFzU3Vic2NyaWJpbmdDbGllbnQoKSkge1xuICAgICAgY2xhc3NTdWJzY3JpcHRpb25zLmRlbGV0ZShzdWJzY3JpcHRpb24uaGFzaCk7XG4gICAgfVxuICAgIC8vIElmIHRoZXJlIGlzIG5vIHN1YnNjcmlwdGlvbnMgdW5kZXIgdGhpcyBjbGFzcywgcmVtb3ZlIGl0IGZyb20gc3Vic2NyaXB0aW9uc1xuICAgIGlmIChjbGFzc1N1YnNjcmlwdGlvbnMuc2l6ZSA9PT0gMCkge1xuICAgICAgdGhpcy5zdWJzY3JpcHRpb25zLmRlbGV0ZShjbGFzc05hbWUpO1xuICAgIH1cbiAgICBydW5MaXZlUXVlcnlFdmVudEhhbmRsZXJzKHtcbiAgICAgIGNsaWVudCxcbiAgICAgIGV2ZW50OiAndW5zdWJzY3JpYmUnLFxuICAgICAgY2xpZW50czogdGhpcy5jbGllbnRzLnNpemUsXG4gICAgICBzdWJzY3JpcHRpb25zOiB0aGlzLnN1YnNjcmlwdGlvbnMuc2l6ZSxcbiAgICAgIHNlc3Npb25Ub2tlbjogc3Vic2NyaXB0aW9uSW5mby5zZXNzaW9uVG9rZW4sXG4gICAgICB1c2VNYXN0ZXJLZXk6IGNsaWVudC5oYXNNYXN0ZXJLZXksXG4gICAgICBpbnN0YWxsYXRpb25JZDogY2xpZW50Lmluc3RhbGxhdGlvbklkLFxuICAgIH0pO1xuXG4gICAgaWYgKCFub3RpZnlDbGllbnQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjbGllbnQucHVzaFVuc3Vic2NyaWJlKHJlcXVlc3QucmVxdWVzdElkKTtcblxuICAgIGxvZ2dlci52ZXJib3NlKFxuICAgICAgYERlbGV0ZSBjbGllbnQ6ICR7cGFyc2VXZWJzb2NrZXQuY2xpZW50SWR9IHwgc3Vic2NyaXB0aW9uOiAke3JlcXVlc3QucmVxdWVzdElkfWBcbiAgICApO1xuICB9XG59XG5cbmV4cG9ydCB7IFBhcnNlTGl2ZVF1ZXJ5U2VydmVyIH07XG4iXX0=