import 'package:admin/model/model.dart';

abstract class ClientRepo {
  Future<ClientInfo> getClientInfo(String id);
  Future<ClientInfo> registerClient(ClientInfo clientInfo);
  Future<ClientInfo> updateClient(ClientInfo clientInfo);
  Future<void> deleteClient(ClientInfo clientInfo);
}
