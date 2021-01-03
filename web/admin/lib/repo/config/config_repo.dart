import 'package:ftauth/ftauth.dart';

abstract class ConfigRepository {
  Future<ClientInfo> loadConfig();
}
