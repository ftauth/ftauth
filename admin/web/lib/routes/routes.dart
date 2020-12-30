import 'package:admin/app_state.dart';
import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:admin/screens/auth/auth_screen.dart';
import 'package:admin/screens/home/home_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

part 'auth.dart';

abstract class RouteInfo {}

class HomeRouteInfo extends RouteInfo {}

class AdminRouteInformationParser extends RouteInformationParser<RouteInfo> {
  final AuthRouteInfoParser _authParser;

  AdminRouteInformationParser(AppState _appState)
      : _authParser = AuthRouteInfoParser(_appState);

  @override
  Future<RouteInfo> parseRouteInformation(
      RouteInformation routeInformation) async {
    final uri = Uri.parse(routeInformation.location);
    final pathComponents = uri.pathSegments;
    if (pathComponents.isEmpty) {
      return HomeRouteInfo();
    }
    switch (pathComponents[0]) {
      case 'auth':
        return _authParser.parseRouteInformation(routeInformation);
      default:
        return HomeRouteInfo();
    }
  }

  @override
  RouteInformation restoreRouteInformation(RouteInfo configuration) {
    switch (configuration.runtimeType) {
      case AuthRouteInfo:
        return _authParser.restoreRouteInformation(configuration);
    }

    return RouteInformation(location: '/');
  }
}

class AdminRouterDelegate extends RouterDelegate<RouteInfo>
    with ChangeNotifier, PopNavigatorRouterDelegateMixin {
  final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();
  final AuthCubit _authCubit;
  final AppState _appState;

  AdminRouterDelegate(this._authCubit, this._appState);

  bool showAuthScreen = true;

  @override
  Widget build(BuildContext context) {
    return BlocListener<AuthCubit, AuthState>(
      listener: (context, state) {
        showAuthScreen = state is! AuthSignedIn;
        notifyListeners();
      },
      child: BlocBuilder<AuthCubit, AuthState>(
        cubit: _authCubit,
        builder: (context, state) {
          return Navigator(
            pages: [
              MaterialPage(
                key: ValueKey('HomeScreen'),
                child: HomeScreen(),
              ),
              if (showAuthScreen)
                MaterialPage(
                  key: ValueKey('AuthScreen'),
                  child: AuthScreen(currentConfiguration),
                ),
            ],
            onPopPage: (route, result) => route.didPop(result),
          );
        },
      ),
    );
  }

  @override
  RouteInfo get currentConfiguration {
    if (showAuthScreen) {
      return _appState.authRouteInfo;
    }
    return HomeRouteInfo();
  }

  @override
  Future<void> setNewRoutePath(RouteInfo configuration) async {}
}
