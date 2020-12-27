import 'dart:convert';

import 'package:admin/model/config/config.dart';
import 'package:admin/model/model.dart';
import 'package:admin/model/server/metadata.dart';
import 'package:admin/util/json.dart';
import 'package:http/http.dart' as http;
import 'package:jose/src/jwk.dart';

import 'metadata_repo.dart';

class MetadataRepoImpl extends MetadataRepo {
  final AppConfig _config;
  final http.Client _client;

  AuthorizationServerMetadata _cached;
  JsonWebKeyStore _keyStore;

  MetadataRepoImpl(this._client, this._config);

  @override
  Future<AuthorizationServerMetadata> loadServerMetadata({
    bool force = false,
  }) async {
    if (_cached == null || force) {
      final path = '${_config.host}/.well-known/oauth-authorization-server';
      final res = await _client.get(path);
      if (res.statusCode != 200) {
        throw ApiException.get(path, res.statusCode, res.body);
      } else {
        final jsonBody = (json.decode(res.body) as Map).cast<String, dynamic>();
        _cached = AuthorizationServerMetadata.fromJson(jsonBody);
      }
    }
    return _cached;
  }

  @override
  Future<AuthorizationServerMetadata> updateServerMetadata(
    AuthorizationServerMetadata metadata,
  ) async {
    final path = '${_config.host}/.well-known/oauth-authorization-server';
    final res = await _client.put(path, body: metadata.toJson());
    if (res.statusCode != 200) {
      throw ApiException.put(path, res.statusCode, res.body);
    } else {
      final jsonBody = (json.decode(res.body) as Map).cast<String, dynamic>();
      _cached = AuthorizationServerMetadata.fromJson(jsonBody);
    }
    return _cached;
  }

  @override
  Future<JsonWebKeyStore> loadKeyStore() async {
    if (_cached == null) {
      await loadServerMetadata();
    }

    if (_keyStore == null) {
      final res = await http.get(_cached.jwksUri);
      if (res.statusCode != 200) {
        throw ApiException.get(_cached.jwksUri, res.statusCode, res.body);
      } else {
        final json = decodeJSON(res.body);
        final jwk = JsonWebKey.fromJson(json);
        _keyStore = JsonWebKeyStore();
        _keyStore.addKey(jwk);
      }
    }

    return _keyStore;
  }
}
