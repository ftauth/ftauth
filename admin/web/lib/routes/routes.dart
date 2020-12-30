import 'dart:async';

import 'package:admin/app_state.dart';
import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:admin/model/tabs.dart';
import 'package:admin/model/template.dart';
import 'package:admin/screens/auth/auth_screen.dart';
import 'package:admin/screens/app/app_screen.dart';
import 'package:admin/screens/client/client_detail_screen.dart';
import 'package:admin/util/regex.dart';
import 'package:admin/util/future.dart';
import 'package:common/common.dart';
import 'package:equatable/equatable.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

part 'auth.dart';
part 'clients.dart';
part 'templates.dart';

abstract class RouteInfo {}

class HomeRouteInfo extends RouteInfo {}

class AdminRouteInformationParser extends RouteInformationParser<RouteInfo> {
  final AuthRouteInfoParser _authParser = AuthRouteInfoParser();
  final ClientRouteInfoParser _clientParser = ClientRouteInfoParser();
  final TemplateRouteInfoParser _templateParser = TemplateRouteInfoParser();
  final AppState _appState;

  AdminRouteInformationParser(this._appState);

  @override
  SynchronousFuture<RouteInfo> parseRouteInformation(
      RouteInformation routeInformation) {
    final uri = Uri.parse(routeInformation.location);
    final pathComponents = uri.pathSegments;
    if (pathComponents.isEmpty) {
      return SynchronousFuture(HomeRouteInfo());
    }
    switch (pathComponents[0]) {
      case 'auth':
        return _authParser.parseRouteInformation(routeInformation);
      case 'clients':
        return _clientParser.parseRouteInformation(routeInformation);
      case 'templates':
        return _templateParser.parseRouteInformation(routeInformation);
      default:
        return SynchronousFuture(HomeRouteInfo());
    }
  }

  @override
  RouteInformation restoreRouteInformation(RouteInfo configuration) {
    switch (configuration.runtimeType) {
      case AuthRouteInfo:
        return _authParser.restoreRouteInformation(configuration);
      case ClientRouteInfo:
        return _clientParser.restoreRouteInformation(configuration);
      case TemplateRouteInfo:
        return _templateParser.restoreRouteInformation(configuration);
    }

    return RouteInformation(location: '/');
  }
}

class AdminRouterDelegate extends RouterDelegate<RouteInfo>
    with ChangeNotifier, PopNavigatorRouterDelegateMixin {
  final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();
  final AuthCubit _authCubit;
  final AppState _appState;

  AdminRouterDelegate(this._authCubit, this._appState) {
    _appState.addListener(notifyListeners);
    // addListener(() {
    //   print('Rebuilding Router...');
    // });
  }

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
                key: ValueKey('AppScreen'),
                child: AppScreen(),
              ),
              if (_appState.isClientDetail)
                MaterialPage(
                  key: ValueKey(_appState.clientRouteInfo.clientId),
                  child: ClientDetailScreen(_appState.clientRouteInfo),
                ),
              if (showAuthScreen)
                MaterialPage(
                  key: ValueKey('AuthScreen'),
                  child: AuthScreen(_appState.authRouteInfo),
                ),
            ],
            onPopPage: (route, result) {
              if (!route.didPop(result)) {
                return false;
              }

              _appState.resetSelected();

              return true;
            },
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
    switch (_appState.selectedTab) {
      case Tabs.clients:
        return _appState.clientRouteInfo;
      case Tabs.templates:
        return _appState.templateRouteInfo;
    }
    return HomeRouteInfo();
  }

  @override
  Future<void> setNewRoutePath(RouteInfo configuration) async {
    switch (configuration.runtimeType) {
      case AuthRouteInfo:
        _appState.authRouteInfo = configuration;
        break;
      case ClientRouteInfo:
        _appState.selectedTab = Tabs.clients;
        _appState.clientRouteInfo = configuration;
        _appState.templateRouteInfo = TemplateRouteInfo.unknown();
        break;
      case TemplateRouteInfo:
        _appState.selectedTab = Tabs.templates;
        _appState.clientRouteInfo = ClientRouteInfo.unknown();
        _appState.templateRouteInfo = configuration;
        break;
      default:
        _appState.selectedTab = Tabs.clients;
        _appState.clientRouteInfo = ClientRouteInfo.unknown();
        _appState.templateRouteInfo = TemplateRouteInfo.unknown();
        break;
    }
  }
}
