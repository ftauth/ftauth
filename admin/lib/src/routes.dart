import 'package:angular_router/angular_router.dart';

import 'client_register_form_component/client_register_form_component.template.dart'
    as client_form_template;
import 'route_paths.dart';

class Routes {
  static final RouteDefinition client = RouteDefinition(
    routePath: RoutePaths.client,
    component: client_form_template.ClientRegisterFormComponentNgFactory,
  );

  static final List<RouteDefinition> all = [client];
}
