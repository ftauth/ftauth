import 'package:admin/app_state.dart';
import 'package:admin/model/tabs.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

class _TabInfo {
  final String title;
  final IconData icon;

  _TabInfo(this.title, this.icon);
}

class HomeDrawerListView extends StatelessWidget {
  final _tabs = [
    _TabInfo('Clients', Icons.person),
    _TabInfo('Templates', Icons.description),
  ];

  @override
  Widget build(BuildContext context) {
    final AppState appState = Provider.of<AppState>(context);
    return ListView(
      children: [
        for (var i = 0; i < _tabs.length; i++)
          ListTile(
            leading: Icon(_tabs[i].icon),
            title: Text(_tabs[i].title),
            selected: appState.selectedTab.index == i,
            onTap: () {
              appState.selectTab(Tabs.values[i]);
            },
          ),
      ],
    );
  }
}
