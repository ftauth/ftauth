import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:admin/routes/routes.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:url_launcher/url_launcher.dart';

class AuthScreen extends StatefulWidget {
  final AuthRouteInfo routeInfo;

  AuthScreen(this.routeInfo);

  @override
  _AuthScreenState createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  @override
  void initState() {
    super.initState();
    final cubit = BlocProvider.of<AuthCubit>(context, listen: false);
    final isInitialized = cubit.initialize();
    if (!widget.routeInfo.isEmpty) {
      isInitialized.then((_) {
        cubit.exchangeToken({
          'code': widget.routeInfo.code,
          'state': widget.routeInfo.state,
        });
      });
    }
  }

  Future<void> _loadLogin(String url) async {
    if (await canLaunch(url)) {
      return launch(url, webOnlyWindowName: '_self');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        automaticallyImplyLeading: false,
      ),
      body: Center(
        child: BlocBuilder<AuthCubit, AuthState>(
          builder: (context, state) {
            bool showIndicator = true;
            String message;
            Widget button;
            if (state is AuthLoading) {
              message = state.message;
            } else if (state is AuthStarted) {
              showIndicator = false;
              button = RaisedButton(
                child: Text('Login'),
                onPressed: () async {
                  final url =
                      await BlocProvider.of<AuthCubit>(context).loadLoginUrl();
                  if (url != null) {
                    _loadLogin(url);
                  }
                },
              );
            } else if (state is AuthSignedOut) {
              showIndicator = false;
              message = 'You are not logged in.';
              button = RaisedButton(
                child: Text('Login'),
                onPressed: () async {
                  final url =
                      await BlocProvider.of<AuthCubit>(context).loadLoginUrl();
                  if (url != null) {
                    _loadLogin(url);
                  }
                },
              );
            } else if (state is AuthFailure) {
              showIndicator = false;
              message = state.message;
              button = RaisedButton(
                child: Text('Try Again'),
                onPressed: () {
                  BlocProvider.of<AuthCubit>(context).initialize();
                },
              );
            }
            return Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                if (message != null)
                  Text(
                    message,
                    style: Theme.of(context).textTheme.headline5,
                  ),
                if (button != null) ...[
                  const SizedBox(height: 20),
                  button,
                ],
                if (showIndicator) ...[
                  const SizedBox(height: 20),
                  CircularProgressIndicator(),
                ],
              ],
            );
          },
        ),
      ),
    );
  }
}
