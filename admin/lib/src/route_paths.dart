import 'package:angular_router/angular_router.dart';

const clientIdParam = 'id';

class RoutePaths {
  static final RoutePath client = RoutePath(path: 'client/:$clientIdParam');
}
