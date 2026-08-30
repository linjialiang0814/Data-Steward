import '../shared_session/protocol_models.dart';

abstract interface class MemoryCenterController {
  bool get canLoadMemory;

  bool get actionBusy;

  void addListener(void Function() listener);

  void removeListener(void Function() listener);

  Future<MemoryCenterSnapshot?> memoryCenter();

  Future<ProductActionExecution> executeAction(ProductAction action);
}
