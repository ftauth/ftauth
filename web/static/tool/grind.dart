import 'dart:io';

import 'package:glob/glob.dart';
import 'package:grinder/grinder.dart';

main(args) => grind(args);

@Task()
test() => TestRunner().testAsync();

@DefaultTask()
// @Depends()
build() {
  // Build index.html
  PubApp.local('build_runner').run(['build', '-r', '-o', 'build']);

  // Build main.dart
  Dart2js.compile(
    File('main.dart'),
    outDir: joinDir(Directory.current, ['js']),
    minify: true,
  );

  // Copy over static assets
  final staticAssets = {
    'web/css/*.css': 'css',
    'web/js/*.js': 'js',
    'web/img': 'img',
    'web/*.html': '',
  };

  final buildDir = joinDir(Directory.current, ['build']);
  for (final entry in staticAssets.entries) {
    final glob = Glob(entry.key);
    final dir = joinDir(buildDir, [entry.value]);
    for (final fileEnt in glob.listSync()) {
      copy(fileEnt, dir);
    }
  }
}

@Task()
clean() => defaultClean();
