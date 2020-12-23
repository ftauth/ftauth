import 'dart:convert';

import 'package:admin/model/model.dart';
import 'package:admin/model/server/metadata.dart';
import 'package:http/http.dart' as http;

import 'metadata_repo.dart';

class MetadataRepoImpl extends MetadataRepo {
  final String host;
  final http.Client _client;

  AuthorizationServerMetadata _cached;

  MetadataRepoImpl(this._client, this.host);

  @override
  Future<AuthorizationServerMetadata> loadServerMetadata({
    bool force = false,
  }) async {
    if (_cached == null || force) {
      final path = '$host/.well-known/oauth-authorization-server';
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
    // TODO: implement updateServerMetadata
    throw UnimplementedError();
  }
}
