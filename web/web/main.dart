@JS()

import 'dart:convert';
import 'dart:html';

import 'package:http/http.dart' as http;
import 'package:js/js.dart';

@JS('JSON.stringify')
external String stringify(Object? o);

void main() {
  final baseUri = window.location.href;
  final loginUrl = Uri.parse(baseUri).resolve('login');
  final loginForm = document.getElementById('loginForm') as FormElement?;
  final username = document.getElementById('username') as InputElement?;
  final password = document.getElementById('password') as InputElement?;

  final opener = window.opener;

  Future<void> login() async {
    final resp = await http.post(
      loginUrl,
      body: jsonEncode({
        'username': username?.value,
        'password': password?.value,
      }),
    );
    if (resp.statusCode != 200) {
      throw Exception('Error: ${resp.body}');
    }
    final parameters = resp.body;

    opener!.postMessage(parameters, '*');
    window.close();
  }

  loginForm?.onSubmit.listen((event) {
    if (opener != null) {
      event.preventDefault();

      login();
    }
  });
}
