import 'dart:async';

import 'package:admin/config/config.dart';
import 'package:ftauth/ftauth.dart';
import 'package:admin/util/json.dart';
import 'package:http/http.dart' as http;

import 'client_repo.dart';

class ClientRepoImpl extends ClientRepo {
  http.Client _client;
  final Completer<void> _loggedIn = Completer();

  final AppConfig _config;

  ClientRepoImpl(Stream<AuthState> authStates, this._config) {
    authStates.firstWhere((state) => state is AuthSignedIn).then((state) {
      _client = (state as AuthSignedIn).client;
      _loggedIn.complete();
    });
  }

  @override
  Future<ClientInfo> getClientInfo(String id) async {
    await _loggedIn.future;
    final path = '${_config.host}/api/admin/clients/$id';
    final res = await _client.get(Uri.tryParse(path));
    if (res.statusCode == 200) {
      final json = decodeJSON(res.body);
      return ClientInfo.fromJson(json);
    } else {
      throw ApiException.get(path, res.statusCode, res.body);
    }
  }

  @override
  Future<ClientInfo> registerClient(ClientInfo clientInfo) async {
    await _loggedIn.future;
    final path = '${_config.host}/api/admin/clients';
    final res = await _client.post(
      Uri.tryParse(path),
      body: clientInfo.toJson(),
    );
    if (res.statusCode == 200) {
      final json = decodeJSON(res.body);
      return ClientInfo.fromJson(json);
    } else {
      throw ApiException.post(path, res.statusCode, res.body);
    }
  }

  @override
  Future<ClientInfo> updateClient(ClientInfo clientInfo) async {
    await _loggedIn.future;
    final path = '${_config.host}/api/admin/clients/${clientInfo.clientId}';
    final res = await _client.put(
      Uri.tryParse(path),
      body: clientInfo.toJson(),
    );
    if (res.statusCode == 200) {
      final json = decodeJSON(res.body);
      return ClientInfo.fromJson(json);
    } else {
      throw ApiException.put(path, res.statusCode, res.body);
    }
  }

  @override
  Future<void> deleteClient(ClientInfo clientInfo) async {
    await _loggedIn.future;
    final path = '${_config.host}/api/admin/clients/${clientInfo.clientId}';
    final res = await _client.delete(Uri.tryParse(path));
    if (res.statusCode != 200) {
      throw ApiException.delete(path, res.statusCode, res.body);
    }
  }

  @override
  Future<List<ClientInfo>> listClients() async {
    await _loggedIn.future;
    final path = '${_config.host}/api/admin/clients';
    final res = await _client.get(Uri.tryParse(path));
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
