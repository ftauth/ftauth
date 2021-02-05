@TestOn('browser')

import 'dart:html';

import 'package:test/test.dart';

void main() {
  group('main', () {
    test('hello', () {
      final hello = document.getElementById('hello');
      expect(hello.innerText, 'Hello, world!');
    });
  });
}
