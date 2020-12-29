import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:common/common.dart';
import 'package:admin/repo/config/config_repo.dart';
import 'package:admin/repo/metadata/metadata_repo.dart';
import 'package:admin/repo/secure_storage/secure_storage_repo.dart';
import 'package:http/http.dart' as http;
import 'package:jose/jose.dart';
import 'package:oauth2/oauth2.dart' as oauth2;

import 'auth_repo.dart';

const INT_MAX = 2147483647;
const _stateLength = 8;
const requestedScopes = ['default', 'admin'];

typedef Interceptor = Future<void> Function(
    http.BaseRequest request, http.StreamedResponse);

class InterceptorClient extends http.BaseClient {
  final http.Client client;
  final List<Interceptor> interceptors;

  InterceptorClient(this.client, [this.interceptors = const []]);

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final response = await client.send(request);
    interceptors.forEach((interceptor) => interceptor(request, response));
    return response;
  }
}

class Credentials implements oauth2.Credentials {
  final Uri _tokenEndpoint;
  final JsonWebToken _accessToken;
  final JsonWebToken _refreshToken;
  final JsonWebKeyStore _keyStore;
  final List<String> _scopes;

  Credentials(
    this._accessToken,
    this._refreshToken,
    this._tokenEndpoint,
    this._keyStore,
    this._scopes,
  );

  static Future<Credentials> fromOAuthCredentials(
    oauth2.Credentials creds,
    JsonWebKeyStore keyStore,
    List<String> scopes,
  ) async {
    final accessToken = await JsonWebToken.decodeAndVerify(
      creds.accessToken,
      keyStore,
    );
    final refreshToken = await JsonWebToken.decodeAndVerify(
      creds.refreshToken,
      keyStore,
    );
    return Credentials(
      accessToken,
      refreshToken,
      creds.tokenEndpoint,
      keyStore,
      scopes,
    );
  }

  @override
  String get accessToken => _accessToken.toCompactSerialization();

  @override
  bool get canRefresh => _refreshToken.claims.expiry.isAfter(DateTime.now());

  @override
  DateTime get expiration => _accessToken.claims.expiry;

  @override
  String get idToken => null;

  @override
  bool get isExpired => _accessToken.claims.expiry.isBefore(DateTime.now());

  @override
  Future<Credentials> refresh({
    String identifier,
    String secret,
    Iterable<String> newScopes,
    bool basicAuth = true,
    http.Client httpClient,
  }) async {
    final creds = await oauth2.Credentials(
      accessToken,
      refreshToken: refreshToken,
      tokenEndpoint: _tokenEndpoint,
    ).refresh(
      identifier: identifier,
      secret: secret,
      httpClient: httpClient,
    );
    return fromOAuthCredentials(creds, _keyStore, _scopes);
  }

  @override
  String get refreshToken => _refreshToken.toCompactSerialization();

  @override
  List<String> get scopes => _scopes;

  @override
  String toJson() => null;

  @override
  Uri get tokenEndpoint => _tokenEndpoint;
}

class AuthRepositoryImpl extends AuthRepository {
  final SecureStorageRepository _storageRepo;
  final MetadataRepo _metadataRepo;
  final ConfigRepository _configRepo;

  AuthRepositoryImpl(this._storageRepo, this._metadataRepo, this._configRepo);

  final StreamController _httpController =
      StreamController<AuthState>.broadcast();
  Stream<AuthState> get httpStream => _httpController.stream;

  oauth2.AuthorizationCodeGrant _grant;
  oauth2.Client _client;

  @override
  http.Client get client => _client;

  String _generateState() {
    final random = Random.secure();
    final bytes = <int>[];
    for (var i = 0; i < _stateLength; i++) {
      final value = random.nextInt(255);
      bytes.add(value);
    }

    return base64UrlEncode(bytes);
  }

  /// Randomly generate a 128 character string to be used as the PKCE code verifier
  static String _createCodeVerifier() {
    const _charset =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    return List.generate(
        128, (i) => _charset[Random.secure().nextInt(_charset.length)]).join();
  }

  @override
  Future<String> getAuthorizationURL() async {
    final serverMetadata = await _metadataRepo.loadServerMetadata();
    final config = await _configRepo.loadConfig();

    final authEndpoint = Uri.parse(serverMetadata.authorizationEndpoint);
    final tokenEndpoint = Uri.parse(serverMetadata.tokenEndpoint);
    final clientId = config.clientId;
    final redirectUri = Uri.parse(config.redirectUris[0]);

    var codeVerifier = await _storageRepo.getString('code_verifier');
    codeVerifier ??= _createCodeVerifier();
    await _storageRepo.setString('code_verifier', codeVerifier);

    _grant = oauth2.AuthorizationCodeGrant(
      clientId,
      authEndpoint,
      tokenEndpoint,
      codeVerifier: codeVerifier,
      secret: '',
    );

    var state = await _storageRepo.getString('state');
    if (state == null) {
      state = _generateState();
      await _storageRepo.setString('state', state);
    }

    return _grant
        .getAuthorizationUrl(
          redirectUri,
          state: state,
          scopes: requestedScopes,
        )
        .toString();
  }

  @override
  Future<void> exchangeToken(Map<String, String> queryParameters) async {
    if (_grant == null) {
      throw AuthException.uninitialized();
    }

    final client = await _grant.handleAuthorizationResponse(queryParameters);
    final keyStore = await _metadataRepo.loadKeyStore();
    final access = await JsonWebToken.decodeAndVerify(
      client.credentials.accessToken,
      keyStore,
    );
    final refresh = await JsonWebToken.decodeAndVerify(
      client.credentials.refreshToken,
      keyStore,
    );
    final interceptorClient = InterceptorClient(
      http.Client(),
      [_unauthorizedInterceptor],
    );
    _client = oauth2.Client(
      Credentials(
        access,
        refresh,
        client.credentials.tokenEndpoint,
        keyStore,
        requestedScopes,
      ),
      httpClient: interceptorClient,
    );
    await _storageRepo.setString(
        'access_token', client.credentials.accessToken);
    await _storageRepo.setString(
        'refresh_token', client.credentials.refreshToken);
    await _storageRepo.deleteKey('state');
    await _storageRepo.deleteKey('code_verifier');
  }

  Future<void> _unauthorizedInterceptor(
    http.BaseRequest request,
    http.StreamedResponse response,
  ) async {
    if (response.statusCode == 401) {
      await logout();
      _httpController.add(AuthSignedOut());
    }
  }

  @override
  Future<AuthState> initialize() async {
    final accessToken = await _storageRepo.getString('access_token');
    final refreshToken = await _storageRepo.getString('refresh_token');

    if (accessToken != null && refreshToken != null) {
      final keyStore = await _metadataRepo.loadKeyStore();
      final access = await JsonWebToken.decodeAndVerify(accessToken, keyStore);
      final refresh =
          await JsonWebToken.decodeAndVerify(refreshToken, keyStore);

      print('Access claims: ${access.claims.toJson()}');
      print('Refresh claims: ${refresh.claims.toJson()}');

      if (access.claims.expiry.isAfter(DateTime.now()) ||
          refresh.claims.expiry.isAfter(DateTime.now())) {
        if (_client == null) {
          final serverMetadata = await _metadataRepo.loadServerMetadata();
          final interceptorClient = InterceptorClient(
            http.Client(),
            [_unauthorizedInterceptor],
          );
          _client = oauth2.Client(
            Credentials(
              access,
              refresh,
              Uri.parse(serverMetadata.tokenEndpoint),
              keyStore,
              requestedScopes,
            ),
            httpClient: interceptorClient,
          );
        }

        return AuthSignedIn();
      } else {
        await _storageRepo.deleteKey('access_token');
        await _storageRepo.deleteKey('refresh_token');
      }
    }

    final state = await _storageRepo.getString('state');
    final codeVerifier = await _storageRepo.getString('code_verifier');

    if (state != null && codeVerifier != null) {
      await getAuthorizationURL();
      return AuthStarted();
    }

    return AuthSignedOut();
  }

  @override
  Future<void> logout() async {
    await _storageRepo.deleteKey('access_token');
    await _storageRepo.deleteKey('refresh_token');
  }
}
