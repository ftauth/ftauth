import 'dart:html';

class AppConfig {
  final String host;

  AppConfig(this.host);

  factory AppConfig.dev() {
    return AppConfig('http://localhost:8000');
  }

  factory AppConfig.prod() {
    return AppConfig('http://${window.location.host}');
  }
}
