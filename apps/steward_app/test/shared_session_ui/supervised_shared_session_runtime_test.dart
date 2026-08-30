import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/shared_session_ui/supervised_shared_session_runtime.dart';

void main() {
  Map<String, String> baseEnvironment() => {
    'DATA_STEWARD_C3_SUPERVISED': '1',
    'DATA_STEWARD_C3_PYTHON': r'C:\runtime\python.exe',
    'DATA_STEWARD_C3_HUB_ROOT': r'C:\runtime\hub',
    'DATA_STEWARD_C3_DATABASE': r'C:\runtime\hub.sqlite3',
    'DATA_STEWARD_C3_IDENTITY_ROOT': r'C:\runtime\identity',
    'DATA_STEWARD_C3_PRIVATE_IPV4': '192.168.1.15',
    'DATA_STEWARD_C3_PRIVATE_PORT': '9443',
  };

  test('explicit Hermes provider and model are accepted as a pair', () {
    final environment = baseEnvironment()
      ..['DATA_STEWARD_C3_HERMES_PROVIDER'] = 'volcengine'
      ..['DATA_STEWARD_C3_HERMES_MODEL'] = 'ep-product-model';

    final parsed = SupervisedSessionEnvironment.fromEnvironment(environment);

    expect(parsed, isNotNull);
    expect(parsed!.agentProvider, 'volcengine');
    expect(parsed.agentModel, 'ep-product-model');
  });

  test('partial or malformed Hermes selection fails closed', () {
    final partial = baseEnvironment()
      ..['DATA_STEWARD_C3_HERMES_PROVIDER'] = 'volcengine';
    final malformed = baseEnvironment()
      ..['DATA_STEWARD_C3_HERMES_PROVIDER'] = 'volcengine'
      ..['DATA_STEWARD_C3_HERMES_MODEL'] = 'bad model';

    expect(SupervisedSessionEnvironment.fromEnvironment(partial), isNull);
    expect(SupervisedSessionEnvironment.fromEnvironment(malformed), isNull);
  });
}
