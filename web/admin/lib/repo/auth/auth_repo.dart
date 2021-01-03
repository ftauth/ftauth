import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:http/http.dart' as http;

abstract class AuthRepository {
  http.Client get client;
  Future<AuthState> initialize();
  Future<String> getAuthorizationURL();
  Future<void> exchangeToken(Map<String, String> queryParameters);
  Future<void> logout();
}
