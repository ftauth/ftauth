class AppConfig {
  final String host;

  AppConfig(this.host);

  factory AppConfig.dev() {
    return AppConfig('http://localhost:8000');
  }

  AppConfig.prod(this.host);
}
