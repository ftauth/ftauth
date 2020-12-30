part of 'routes.dart';

class AuthRouteInfo extends RouteInfo {
  final String code;
  final String state;

  AuthRouteInfo(this.code, this.state);

  AuthRouteInfo.empty()
      : code = null,
        state = null;

  bool get isEmpty => code == null && state == null;
}

class AuthRouteInfoParser extends RouteInformationParser<AuthRouteInfo> {
  final AppState _appState;

  AuthRouteInfoParser(this._appState);

  @override
  Future<AuthRouteInfo> parseRouteInformation(
      RouteInformation routeInformation) async {
    final uri = Uri.parse(routeInformation.location);
    if (uri.queryParameters.containsKey('code') &&
        uri.queryParameters.containsKey('state')) {
      return _appState.authRouteInfo = AuthRouteInfo(
        uri.queryParameters['code'],
        uri.queryParameters['state'],
      );
    }
    return AuthRouteInfo.empty();
  }

  @override
  RouteInformation restoreRouteInformation(RouteInfo configuration) {
    return RouteInformation(location: '/auth');
  }
}
