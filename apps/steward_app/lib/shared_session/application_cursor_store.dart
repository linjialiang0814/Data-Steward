import 'dart:io';

import 'package:path_provider/path_provider.dart';

import 'file_cursor_store.dart';

Future<FileCursorStore> createApplicationCursorStore() async {
  final support = await getApplicationSupportDirectory();
  return FileCursorStore(Directory('${support.path}/shared_session_cursors'));
}
