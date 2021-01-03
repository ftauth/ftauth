import 'package:admin/model/tabs.dart';
import 'package:admin/routes/routes.dart';
import 'package:ftauth/ftauth.dart';
import 'package:flutter/foundation.dart';

class AppState extends ChangeNotifier {
  AuthRouteInfo authRouteInfo = AuthRouteInfo.empty();
  ClientRouteInfo clientRouteInfo = ClientRouteInfo.unknown();
  TemplateRouteInfo templateRouteInfo = TemplateRouteInfo.unknown();

  Tabs selectedTab = Tabs.clients;

  bool get isClientDetail => clientRouteInfo.isDetail;

  void resetSelected() {
    clientRouteInfo = ClientRouteInfo.unknown();
    templateRouteInfo = TemplateRouteInfo.unknown();
    notifyListeners();
  }

  void selectTab(Tabs tab) {
    selectedTab = tab;
    notifyListeners();
  }

  void selectClient(String clientId, {ClientInfo clientInfo}) {
    clientRouteInfo = ClientRouteInfo(clientId, clientInfo: clientInfo);
    notifyListeners();
  }
}
