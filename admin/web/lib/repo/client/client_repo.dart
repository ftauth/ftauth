import 'package:common/common.dart';

abstract class ClientRepo {
  Future<List<ClientInfo>> listClients();
  Future<ClientInfo> getClientInfo(String id);
  Future<ClientInfo> registerClient(ClientInfo clientInfo);
  Future<ClientInfo> updateClient(ClientInfo clientInfo);
  Future<void> deleteClient(ClientInfo clientInfo);
}
