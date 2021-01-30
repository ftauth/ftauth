import 'package:admin/app_state.dart';
import 'package:admin/screens/client/client_list_view.dart';
import 'package:admin/screens/templates/templates_screen.dart';
import 'package:admin/screens/app/home_drawer_list_view.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

const _drawerWidth = 275.0;

class AppScreen extends StatelessWidget {
  final _routes = <WidgetBuilder>[
    (_) => ClientListView(),
    (_) => TemplateScreen(),
  ];

  @override
  Widget build(BuildContext context) {
    final AppState appState = Provider.of<AppState>(context);
    return LayoutBuilder(
      builder: (context, constraints) {
        final bool showDrawer = constraints.maxWidth < 100;
        return Scaffold(
          appBar: AppBar(
            title: Text('FTAuth Admin'),
          ),
          drawer: showDrawer ? Drawer(child: HomeDrawerListView()) : null,
          body: Center(
            child: Row(
              children: [
                if (!showDrawer) ...[
                  Container(
                    width: _drawerWidth,
                    child: HomeDrawerListView(),
                  ),
                  const VerticalDivider(),
                ],
                Expanded(
                  child: _routes[appState.selectedTab.index](context),
                ),
              ],
            ),
          ),
        );
      },
    );
  }
}
