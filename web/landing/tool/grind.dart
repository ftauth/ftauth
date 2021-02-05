import 'dart:convert';
import 'dart:io';

import 'package:grinder/grinder.dart';

main(args) => grind(args);

@Task()
test() => TestRunner().testAsync(platformSelector: ['chrome']);

@DefaultTask()
// @Depends()
build() {
  // Build index.html
  PubApp.local('build_runner').run(['build', '-r', '-o', 'web:build']);
}

@Task()
@Depends(build)
serve() async {
  await Process.start(Platform.executable, ['bin/serve.dart']).then((Process process) {
    process.stdout.transform(utf8.decoder).listen(stdout.write);
  });
}

@Task()
clean() => defaultClean();
