import 'package:common/common.dart';

abstract class ConfigRepository {
  Future<ClientInfo> loadConfig();
}
