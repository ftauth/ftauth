import 'package:flutter/material.dart';

class AuthRouteInfo {
  final String state;
  final String code;

  AuthRouteInfo(this.code, this.state);

  AuthRouteInfo.empty()
      : code = null,
        state = null;

  bool get isEmpty => code == null && state == null;
}

class AuthRouteInfoParser extends RouteInformationParser<AuthRouteInfo> {
  @override
  Future<AuthRouteInfo> parseRouteInformation(
      RouteInformation routeInformation) async {
    final uri = Uri.parse(routeInformation.location);
    if (uri.queryParameters.containsKey('code') &&
        uri.queryParameters.containsKey('state')) {
      return AuthRouteInfo(
        uri.queryParameters['code'],
        uri.queryParameters['state'],
      );
    }
    return AuthRouteInfo.empty();
  }
}

class AuthRouterDelegate extends RouterDelegate<AuthRouteInfo>
    with ChangeNotifier, PopNavigatorRouterDelegateMixin<AuthRouteInfo> {
  @override
  Widget build(BuildContext context) {
    return Navigator(
      pages: [],
    );
  }

  @override
  // TODO: implement navigatorKey
  GlobalKey<NavigatorState> get navigatorKey => throw UnimplementedError();

  @override
  Future<void> setNewRoutePath(AuthRouteInfo configuration) {
    // TODO: implement setNewRoutePath
    throw UnimplementedError();
  }
}
