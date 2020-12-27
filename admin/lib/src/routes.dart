import 'package:angular_router/angular_router.dart';

import 'home/home_component.template.dart' as home_template;
import 'client/client_list_component/client_list_component.template.dart'
    as client_list_template;
import 'client/client_form_component/client_form_component.template.dart'
    as client_form_template;
import 'auth/auth_component/auth_component.template.dart' as auth_template;
import 'route_paths.dart';

class Routes {
  static final RouteDefinition home = RouteDefinition(
    routePath: RoutePaths.home,
    component: home_template.HomeComponentNgFactory,
  );
  static final RouteDefinition auth = RouteDefinition(
    useAsDefault: true,
    routePath: RoutePaths.auth,
    component: auth_template.AuthComponentNgFactory,
  );
  static final RouteDefinition clients = RouteDefinition(
    routePath: RoutePaths.clients,
    component: client_list_template.ClientListComponentNgFactory,
  );
  static final RouteDefinition client = RouteDefinition(
    routePath: RoutePaths.client,
    component: client_form_template.ClientRegisterFormComponentNgFactory,
  );

  static final List<RouteDefinition> all = [
    home,
    auth,
    client,
    clients,
  ];
}
