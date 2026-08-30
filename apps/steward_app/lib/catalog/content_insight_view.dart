import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'content_insight.dart';

const defaultStudyPackRequest = '请结合今天的资料生成一份重点简报';

final class ContentInsightView extends StatefulWidget {
  const ContentInsightView({
    required this.pack,
    required this.busy,
    required this.canGenerate,
    required this.onGenerate,
    this.message,
    super.key,
  });

  final StudyPack? pack;
  final bool busy;
  final bool canGenerate;
  final ValueChanged<String>? onGenerate;
  final String? message;

  @override
  State<ContentInsightView> createState() => _ContentInsightViewState();
}

final class _ContentInsightViewState extends State<ContentInsightView> {
  final TextEditingController _request = TextEditingController();

  @override
  void dispose() {
    _request.dispose();
    super.dispose();
  }

  void _submit() {
    if (!widget.canGenerate || widget.busy || widget.onGenerate == null) return;
    final value = _request.text.trim();
    widget.onGenerate!(value.isEmpty ? defaultStudyPackRequest : value);
  }

  KeyEventResult _handleKeyEvent(FocusNode _, KeyEvent event) {
    if (event is! KeyDownEvent ||
        (event.logicalKey != LogicalKeyboardKey.enter &&
            event.logicalKey != LogicalKeyboardKey.numpadEnter)) {
      return KeyEventResult.ignored;
    }
    if (HardwareKeyboard.instance.isShiftPressed) {
      return KeyEventResult.ignored;
    }
    final composing = _request.value.composing;
    if (composing.isValid && !composing.isCollapsed) {
      return KeyEventResult.ignored;
    }
    _submit();
    return KeyEventResult.handled;
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final value = widget.pack;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.auto_awesome, color: theme.colorScheme.primary),
                const SizedBox(width: 10),
                Expanded(
                  child: Text('AI 资料简报', style: theme.textTheme.titleLarge),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              widget.canGenerate
                  ? '只分析已明确授权的 TXT、Markdown、DOCX、PPTX 与文本型 PDF；加密或异常文档会被安全跳过，不会执行其中的命令，也不会修改文件。'
                  : '需要内容理解授权后才能生成；今日资料的元数据分组仍可正常使用。',
            ),
            const SizedBox(height: 14),
            Focus(
              onKeyEvent: _handleKeyEvent,
              child: TextField(
                key: const Key('content-insight-request'),
                controller: _request,
                enabled: widget.canGenerate && !widget.busy,
                minLines: 1,
                maxLines: 3,
                maxLength: 500,
                keyboardType: TextInputType.multiline,
                textInputAction: TextInputAction.newline,
                decoration: const InputDecoration(
                  labelText: '想让 Hermes 怎样分析？',
                  hintText: defaultStudyPackRequest,
                  helperText: 'Enter 发送，Shift+Enter 换行',
                  border: OutlineInputBorder(),
                ),
              ),
            ),
            const SizedBox(height: 10),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.icon(
                key: const Key('content-insight-submit'),
                onPressed: widget.canGenerate && !widget.busy ? _submit : null,
                icon: const Icon(Icons.arrow_upward),
                label: Text(widget.busy ? '正在理解…' : '交给 Hermes'),
              ),
            ),
            if (widget.message != null) ...[
              const SizedBox(height: 10),
              Text(widget.message!),
            ],
            if (value != null) ...[
              const Divider(height: 28),
              Text(value.title, style: theme.textTheme.titleMedium),
              const SizedBox(height: 8),
              Text(value.summary),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  for (final topic in value.topics) Chip(label: Text(topic)),
                ],
              ),
              const SizedBox(height: 12),
              for (final point in value.reviewPoints)
                Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text('•  '),
                      Expanded(child: Text(point)),
                    ],
                  ),
                ),
              const SizedBox(height: 4),
              Text(
                value.source == 'hermes' ? '由 Hermes 受控分析生成' : '由本机安全摘要生成',
                style: theme.textTheme.bodySmall,
              ),
            ],
          ],
        ),
      ),
    );
  }
}
