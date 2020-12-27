import 'dart:html';

import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:angular/angular.dart';
import 'package:angular_components/angular_components.dart';
import 'package:angular_router/angular_router.dart';

import 'src/routes.dart';
import 'src/route_paths.dart';

@Component(
  selector: 'my-app',
  styleUrls: [
    'app_component.css',
    'package:angular_components/app_layout/layout.scss.css',
  ],
  templateUrl: 'app_component.html',
  directives: [
    coreDirectives,
    DeferredContentAware,
    DeferredContentDirective,
    MaterialIconComponent,
    MaterialButtonComponent,
    MaterialPersistentDrawerDirective,
    MaterialListComponent,
    MaterialListItemComponent,
    routerDirectives,
  ],
  exports: [
    RoutePaths,
    Routes,
  ],
)
class AppComponent implements OnInit {
  final AuthCubit _authCubit;
  final Router _router;
  final Location _location;

  AppComponent(this._authCubit, this._router, this._location);

  bool get isInitializingAuth => _authCubit.state is AuthInitial;
  bool get isLoggedIn => _authCubit.state is AuthSignedIn;
  bool get showLoggedOutBanner => _authCubit.state is AuthSignedOut;

  @override
  void ngOnInit() async {
    await _authCubit.initialize();
  }

  void navigateToClients() => _router.navigate(Routes.clients.toUrl());

  Future<void> login() async {
    final loginUrl = await _authCubit.loadLoginUrl();
    window.location.replace(loginUrl);
  }

  void logout() {}
}
