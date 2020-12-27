import 'dart:html';

import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:admin/src/routes.dart';
import 'package:admin/util/cookie.dart';
import 'package:angular/angular.dart';
import 'package:angular/core.dart';
import 'package:angular_components/angular_components.dart';
import 'package:angular_components/material_spinner/material_spinner.dart';
import 'package:angular_router/angular_router.dart';

@Component(
  selector: 'auth',
  templateUrl: 'auth_component.html',
  styleUrls: [
    'auth_component.css',
  ],
  directives: [
    coreDirectives,
    MaterialSpinnerComponent,
    MaterialButtonComponent,
  ],
)
class AuthComponent implements OnActivate {
  final AuthCubit _authCubit;
  final Router _router;

  AuthComponent(this._authCubit, this._router);

  bool get showLoginButton => true;
  bool get isLoading => _authCubit.state is AuthLoading;
  bool get isError =>
      _authCubit.state is AuthFailure || _authCubit.state is AuthSignedOut;

  String get errorTitle {
    if (_authCubit.state is AuthFailure) {
      return 'Error';
    } else if (_authCubit.state is AuthSignedOut) {
      return 'Unauthorized';
    }
    return '';
  }

  String get errorMessage {
    if (_authCubit.state is AuthFailure) {
      return (_authCubit.state as AuthFailure).exception.message;
    } else if (_authCubit.state is AuthSignedOut) {
      return 'Please return to login.';
    }
    return '';
  }

  @override
  void onActivate(RouterState previous, RouterState current) async {
    await _authCubit.firstWhere((state) => state is! AuthInitial);
    final queryParams = current.queryParameters;
    if (queryParams.containsKey('code') && queryParams.containsKey('state')) {
      await _authCubit.exchangeToken(queryParams);
    } else if (queryParams.containsKey('error')) {
      _authCubit.handleAuthorizationError(queryParams);
    }
    init();
  }

  void init() async {
    print('auth on init');
    await for (var state in _authCubit.states) {
      if (state is AuthSignedOut || state is AuthFailure) {
        print('Navigating to: ' + Routes.auth.toUrl());
        final res = await _router.navigate(Routes.auth.toUrl());
        print(res.toString());
      } else if (state is AuthSignedIn) {
        await _router.navigate(Routes.home.toUrl());
      }
    }
  }
}
