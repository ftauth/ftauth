import 'package:flutter/foundation.dart';

extension SynchronousFutureX<T> on SynchronousFuture<T> {
  SynchronousFuture<T> saveAndReturn(void Function(T value) save) {
    then(save);
    return this;
  }
}
