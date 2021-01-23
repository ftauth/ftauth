import 'package:admin/routes/routes.dart';
import 'package:flutter/material.dart';
import 'package:ftauth_flutter/ftauth_flutter.dart';

class AuthScreen extends StatefulWidget {
  final AuthRouteInfo routeInfo;

  AuthScreen(this.routeInfo);

  @override
  _AuthScreenState createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  @override
  void didChangeDependencies() async {
    super.didChangeDependencies();

    final config = FTAuth.of(context);
    final isLoggedIn = (await config.authStates.first) is AuthSignedIn;
    if (!widget.routeInfo.isEmpty && !isLoggedIn) {
      config.exchangeAuthorizationCode({
        'code': widget.routeInfo.code,
        'state': widget.routeInfo.state,
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        automaticallyImplyLeading: false,
      ),
      body: Center(
        child: StreamBuilder<AuthState>(
          stream: FTAuth.of(context).authStates,
          initialData: const AuthLoading(),
          builder: (context, snapshot) {
            final state = snapshot.data;

            bool showIndicator = true;
            String message;
            Widget button;
            if (state is AuthLoading) {
              message = 'Loading...';
            } else if (state is AuthSignedOut) {
              showIndicator = false;
              message = 'You are not logged in.';
              button = RaisedButton(
                child: Text('Login'),
                onPressed: () async {
                  await FTAuth.of(context).authorize();
                },
              );
            } else if (state is AuthFailure) {
              showIndicator = false;
              message = state.message;
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
