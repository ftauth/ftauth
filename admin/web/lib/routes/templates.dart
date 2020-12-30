part of 'routes.dart';

class TemplateRouteInfo extends RouteInfo {
  final Templates template;

  TemplateRouteInfo(this.template);

  TemplateRouteInfo.unknown() : template = null;

  bool get isUnknown => template == null;
}

class TemplateRouteInfoParser
    extends RouteInformationParser<TemplateRouteInfo> {
  @override
  SynchronousFuture<TemplateRouteInfo> parseRouteInformation(
      RouteInformation routeInformation) {
    final Uri uri = Uri.parse(routeInformation.location);
    final List<String> pathComponents = uri.pathSegments;

    // matches /templates/:templateName
    if (pathComponents.length == 2) {
      final templateStr = pathComponents[1];
      final template = Templates.values.firstWhere(
        (templ) => templ.stringify() == templateStr,
        orElse: () => null,
      );
      if (template != null) {
        return SynchronousFuture(TemplateRouteInfo(template));
      }
    }

    // matches /templates and unknown template names
    return SynchronousFuture(TemplateRouteInfo.unknown());
  }

  @override
  RouteInformation restoreRouteInformation(TemplateRouteInfo configuration) {
    if (!configuration.isUnknown) {
      return RouteInformation(
          location: '/templates/${configuration.template.stringify()}');
    }
    return RouteInformation(location: '/templates');
  }
}
