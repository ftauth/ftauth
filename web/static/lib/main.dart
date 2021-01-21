import 'dart:async';
import 'dart:convert';
import 'dart:html';

import 'package:codemirror/codemirror.dart';
import 'package:email_validator/email_validator.dart';
import 'package:http/http.dart' as http;
import 'package:pool/pool.dart';

final _httpClient = _ThrottleClient(
  1,
  _DebounceClient(const Duration(milliseconds: 500)),
);

void main() {
  final options = {
    'mode': 'dart',
    'theme': 'material',
  };
  final editor = CodeMirror.fromElement(
    querySelector('#codeContainer'),
    options: options,
  );
  editor.getDoc().setValue('''
import 'package:ftauth_flutter/ftauth_flutter.dart';

Future<void> main() async {
  final config = FTAuthConfig(
    gatewayUrl: 'https://myapp.ftauth.dev',
    clientId: '1deddb6d-7957-40a1-a323-77725cecfa18',
    redirectUri: kIsWeb ? 'http://localhost:8080/#/auth' : 'myapp://auth',
  );

  await FTAuth.initFlutter(config: config);
}''');

  // Register emails on submission
  document.querySelector('#submitEmail').onClick.listen((event) async {
    print('clicked');
    final input = document.querySelector('#email') as InputElement;
    final button = document.querySelector('#submitEmail');
    final email = input.value;
    final error = await _registerEmail(email);
    final emailResult = document.querySelector('#emailResult');
    if (error != null) {
      emailResult.text = error;
      input.classes.add('error');
      button.classes.add('error');
    } else {
      emailResult.text = 'Email submitted \u2713';
      input.classes.add('success');
      button.classes.add('success');
    }
  });
}

bool _validateEmail(String email) {
  return EmailValidator.validate(email);
}

Future<String> _registerEmail(String email) async {
  print('validating email: $email');
  if (!_validateEmail(email)) {
    return 'Invalid email.';
  }
  try {
    final resp = await _httpClient.post(
      '/register',
      body: jsonEncode({
        'email': email,
      }),
    );
    if (resp.statusCode == 200) {
      return null;
    }
    return resp.body.isNotEmpty
        ? resp.body
        : 'An error occurred. Please try again.';
  } on Exception {
    return 'An error occurred. Please try again.';
  }
}

/// A middleware client that throttles the number of concurrent requests.
///
/// As long as the number of requests is within the limit, this works just like
/// a normal client. If a request is made beyond the limit, the underlying HTTP
/// request won't be sent until other requests have completed.
class _ThrottleClient extends http.BaseClient {
  final Pool _pool;
  final http.Client _inner;

  /// Creates a new client that allows no more than [maxActiveRequests]
  /// concurrent requests.
  ///
  /// If [inner] is passed, it's used as the inner client for sending HTTP
  /// requests. It defaults to `new http.Client()`.
  _ThrottleClient(int maxActiveRequests, this._inner)
      : _pool = Pool(maxActiveRequests);

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    var resource = await _pool.request();

    http.StreamedResponse response;
    try {
      response = await _inner.send(request);
    } catch (_) {
      resource.release();
      rethrow;
    }

    var stream = response.stream.transform(
        StreamTransformer<List<int>, List<int>>.fromHandlers(
            handleDone: (sink) {
      resource.release();
      sink.close();
    }));
    return http.StreamedResponse(stream, response.statusCode,
        contentLength: response.contentLength,
        request: response.request,
        headers: response.headers,
        isRedirect: response.isRedirect,
        persistentConnection: response.persistentConnection,
        reasonPhrase: response.reasonPhrase);
  }

  @override
  void close() => _inner.close();
}

class _DebounceClient extends http.BaseClient {
  final Duration _debounceTime;
  final http.Client _inner;

  _DebounceClient(this._debounceTime) : _inner = http.Client();

  Future<void> _countdownTimer;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    await (_countdownTimer ??= Future<void>.delayed(_debounceTime));
    _countdownTimer = null;
    return _inner.send(request);
  }

  @override
  void close() {
    _inner.close();
    super.close();
  }
}
