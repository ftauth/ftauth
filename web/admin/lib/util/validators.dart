import 'package:ftauth_flutter/ftauth_flutter.dart';

String redirectUriValidator(ClientInfo clientInfo, String redirectUri) {
  final uri = Uri.tryParse(redirectUri);
  if (uri == null) {
    return 'Invalid URI';
  }
}
