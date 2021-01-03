part of 'routes.dart';

class ClientRouteInfo extends RouteInfo with EquatableMixin {
  final String clientId;
  final ClientInfo clientInfo;

  ClientRouteInfo(this.clientId, {this.clientInfo});

  ClientRouteInfo.unknown()
      : clientId = null,
        clientInfo = null;

  bool get isDetail => clientId != null;

  @override
  List<Object> get props => [clientId, clientInfo];
}

class ClientRouteInfoParser extends RouteInformationParser<ClientRouteInfo> {
  @override
  SynchronousFuture<ClientRouteInfo> parseRouteInformation(
      RouteInformation routeInformation) {
    final Uri uri = Uri.parse(routeInformation.location);
    final List<String> pathComponents = uri.pathSegments;

    // matches /clients/:id
    if (pathComponents.length == 2) {
      final String clientId = pathComponents[1];
      if (v4Regex.hasMatch(clientId)) {
        return SynchronousFuture(ClientRouteInfo(clientId));
      }
    }

    // matches /clients and unknown clients
    return SynchronousFuture(ClientRouteInfo.unknown());
  }

  @override
  RouteInformation restoreRouteInformation(ClientRouteInfo configuration) {
    if (configuration.isDetail) {
      return RouteInformation(location: '/clients/${configuration.clientId}');
    }
    return RouteInformation(location: '/clients');
  }
}
