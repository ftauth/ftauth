extension ListX<T> on List<T> {
  List<T> spacedBy(T val) {
    if (length <= 1) {
      return this;
    }
    final result = <T>[];
    for (var i = 0; i < length - 1; i++) {
      result.add(this[i]);
      result.add(val);
    }
    result.add(last);
    return result;
  }

  List<T> spacedByAll(List<T> vals) {
    if (length <= 1) {
      return this;
    }
    final result = <T>[];
    for (var i = 0; i < length - 1; i++) {
      result.add(this[i]);
      result.addAll(vals);
    }
    result.add(last);
    return result;
  }
}
