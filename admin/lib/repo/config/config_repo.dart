import 'package:admin/model/model.dart';

abstract class ConfigRepository {
  Future<ClientInfo> loadConfig();
}
