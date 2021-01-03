#/bin/bash

set -e

flutter --version
flutter pub get
flutter test
flutter config --enable-web
flutter build web
