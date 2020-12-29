import 'package:admin/config/config.dart';
import 'package:common/common.dart';
import 'package:admin/repo/auth/auth_repo.dart';
import 'package:admin/util/json.dart';
import 'package:http/http.dart' as http;

import 'client_repo.dart';

class ClientRepoImpl extends ClientRepo {
  final AuthRepository _authRepo;
  final AppConfig _config;

  ClientRepoImpl(this._authRepo, this._config);

  http.Client get client {
    if (_authRepo.client == null) {
      throw AuthException.uninitialized();
    }
    return _authRepo.client;
  }

  @override
  Future<ClientInfo> getClientInfo(String id) async {
    final path = '${_config.host}/api/admin/clients/$id';
    final res = await client.get(path);
    if (res.statusCode == 200) {
      final json = decodeJSON(res.body);
      return ClientInfo.fromJson(json);
    } else {
      throw ApiException.get(path, res.statusCode, res.body);
    }
  }

  @override
  Future<ClientInfo> registerClient(ClientInfo clientInfo) async {
    final path = '${_config.host}/api/admin/clients';
    final res = await client.post(path, body: clientInfo.toJson());
    if (res.statusCode == 200) {
      final json = decodeJSON(res.body);
      return ClientInfo.fromJson(json);
    } else {
      throw ApiException.post(path, res.statusCode, res.body);
    }
  }

  @override
  Future<ClientInfo> updateClient(ClientInfo clientInfo) async {
    final path = '${_config.host}/api/admin/clients/${clientInfo.clientId}';
    final res = await client.put(path, body: clientInfo.toJson());
    if (res.statusCode == 200) {
      final json = decodeJSON(res.body);
      return ClientInfo.fromJson(json);
    } else {
      throw ApiException.put(path, res.statusCode, res.body);
    }
  }

  @override
  Future<void> deleteClient(ClientInfo clientInfo) async {
    final path = '${_config.host}/api/admin/clients/${clientInfo.clientId}';
    final res = await client.delete(path);
    if (res.statusCode != 200) {
      throw ApiException.delete(path, res.statusCode, res.body);
    }
  }

  @override
  Future<List<ClientInfo>> listClients() async {
    final path = '${_config.host}/api/admin/clients';
    final res = await client.get(path);
    if (res.statusCode == 200) {
      final json = decodeJSONArray(res.body);
      final clients = <ClientInfo>[];
      for (var el in json) {
        clients.add(ClientInfo.fromJson(el));
      }
      return clients;
    } else {
      throw ApiException.get(path, res.statusCode, res.body);
    }
  }
}
