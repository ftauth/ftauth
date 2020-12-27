import 'dart:convert';
import 'dart:math';

import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:admin/model/exception.dart';
import 'package:admin/repo/config/config_repo.dart';
import 'package:admin/repo/metadata/metadata_repo.dart';
import 'package:admin/repo/secure_storage/secure_storage_repo.dart';
import 'package:http/http.dart' as http;
import 'package:jose/jose.dart';
import 'package:oauth2/oauth2.dart' as oauth2;

import 'auth_repo.dart';

const INT_MAX = 2147483647;
const _stateLength = 8;
const requestedScopes = ['default', 'admin', 'unknown'];

class AuthRepositoryImpl extends AuthRepository {
  final SecureStorageRepository _storageRepo;
  final MetadataRepo _metadataRepo;
  final ConfigRepository _configRepo;

  AuthRepositoryImpl(this._storageRepo, this._metadataRepo, this._configRepo);

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
    state ??= _generateState();
    await _storageRepo.setString('state', state);

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

    try {
      _client = await _grant.handleAuthorizationResponse(queryParameters);
      await _storageRepo.setString(
          'access_token', _client.credentials.accessToken);
      await _storageRepo.setString(
          'refresh_token', _client.credentials.refreshToken);
      await _storageRepo.deleteKey('state');
      await _storageRepo.deleteKey('code_verifier');
    } catch (e) {
      throw AuthException(e.toString());
    }
  }

  @override
  Future<AuthState> initialize() async {
    final accessToken = await _storageRepo.getString('access_token');
    final refreshToken = await _storageRepo.getString('refresh_token');

    if (accessToken != null && refreshToken != null) {
      final access = JsonWebSignature.fromCompactSerialization(accessToken);
      final refresh = JsonWebSignature.fromCompactSerialization(refreshToken);

      final accessClaims =
          JsonWebTokenClaims.fromJson(access.unverifiedPayload.jsonContent);
      final refreshClaims =
          JsonWebTokenClaims.fromJson(refresh.unverifiedPayload.jsonContent);

      print('Access claims: ${accessClaims.toJson()}');
      print('Refresh claims: ${refreshClaims.toJson()}');

      if (accessClaims.expiry.isAfter(DateTime.now()) ||
          refreshClaims.expiry.isAfter(DateTime.now())) {
        if (_client == null) {
          final serverMetadata = await _metadataRepo.loadServerMetadata();
          _client = oauth2.Client(
            oauth2.Credentials(
              accessToken,
              refreshToken: refreshToken,
              tokenEndpoint: Uri.parse(serverMetadata.tokenEndpoint),
              expiration: accessClaims.expiry,
              scopes: requestedScopes,
            ),
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
