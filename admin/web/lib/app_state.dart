import 'package:admin/routes/routes.dart';
import 'package:flutter/foundation.dart';

class AppState extends ChangeNotifier {
  AuthRouteInfo _authRouteInfo = AuthRouteInfo.empty();
  AuthRouteInfo get authRouteInfo => _authRouteInfo;
  set authRouteInfo(AuthRouteInfo newValue) {
    _authRouteInfo = newValue;
    notifyListeners();
  }
}
