import 'package:angular_router/angular_router.dart';

const clientIdParam = 'id';

class RoutePaths {
  static final RoutePath home = RoutePath(path: 'home');
  static final RoutePath clients = RoutePath(path: 'clients');
  static final RoutePath client = RoutePath(path: 'clients/:$clientIdParam');
  static final RoutePath auth = RoutePath(path: 'auth');
  static final RoutePath signedIn = RoutePath(path: 'signedin');
}
