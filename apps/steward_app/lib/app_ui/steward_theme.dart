import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

abstract final class StewardSpacing {
  static const xxs = 4.0;
  static const xs = 8.0;
  static const sm = 12.0;
  static const md = 16.0;
  static const lg = 24.0;
  static const xl = 32.0;
}

abstract final class StewardRadii {
  static const sm = 12.0;
  static const md = 18.0;
  static const lg = 24.0;
}

abstract final class StewardTheme {
  static const _seed = Color(0xFF3155D9);

  static ThemeData light() => _build(Brightness.light);

  static ThemeData dark() => _build(Brightness.dark);

  static ThemeData _build(Brightness brightness) {
    final scheme = ColorScheme.fromSeed(
      seedColor: _seed,
      brightness: brightness,
    );
    final dark = brightness == Brightness.dark;
    final base = ThemeData(
      useMaterial3: true,
      brightness: brightness,
      colorScheme: scheme,
      visualDensity: VisualDensity.standard,
    );
    final radius = BorderRadius.circular(StewardRadii.md);
    return base.copyWith(
      scaffoldBackgroundColor: dark
          ? const Color(0xFF0E1118)
          : const Color(0xFFF5F7FC),
      textTheme: base.textTheme.copyWith(
        headlineLarge: base.textTheme.headlineLarge?.copyWith(
          fontWeight: FontWeight.w700,
          letterSpacing: -0.8,
        ),
        headlineMedium: base.textTheme.headlineMedium?.copyWith(
          fontWeight: FontWeight.w700,
          letterSpacing: -0.5,
        ),
        titleLarge: base.textTheme.titleLarge?.copyWith(
          fontWeight: FontWeight.w700,
        ),
        titleMedium: base.textTheme.titleMedium?.copyWith(
          fontWeight: FontWeight.w600,
        ),
      ),
      cardTheme: CardThemeData(
        elevation: 0,
        margin: EdgeInsets.zero,
        color: dark ? const Color(0xFF171B24) : Colors.white,
        shape: RoundedRectangleBorder(
          borderRadius: radius,
          side: BorderSide(color: scheme.outlineVariant.withValues(alpha: .7)),
        ),
      ),
      appBarTheme: AppBarTheme(
        elevation: 0,
        scrolledUnderElevation: 0,
        backgroundColor: Colors.transparent,
        surfaceTintColor: Colors.transparent,
        systemOverlayStyle: dark
            ? SystemUiOverlayStyle.light
            : SystemUiOverlayStyle.dark,
        titleTextStyle: base.textTheme.titleLarge?.copyWith(
          color: scheme.onSurface,
          fontWeight: FontWeight.w700,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: dark ? const Color(0xFF1D222D) : Colors.white,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(StewardRadii.sm),
          borderSide: BorderSide(color: scheme.outlineVariant),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(StewardRadii.sm),
          borderSide: BorderSide(color: scheme.outlineVariant),
        ),
      ),
      navigationBarTheme: NavigationBarThemeData(
        height: 72,
        elevation: 0,
        backgroundColor: dark ? const Color(0xFF151922) : Colors.white,
        indicatorColor: scheme.primaryContainer,
        labelTextStyle: WidgetStatePropertyAll(
          base.textTheme.labelMedium?.copyWith(fontWeight: FontWeight.w600),
        ),
      ),
      navigationRailTheme: NavigationRailThemeData(
        elevation: 0,
        backgroundColor: dark ? const Color(0xFF151922) : Colors.white,
        indicatorColor: scheme.primaryContainer,
        selectedIconTheme: IconThemeData(color: scheme.onPrimaryContainer),
        selectedLabelTextStyle: TextStyle(
          color: scheme.primary,
          fontWeight: FontWeight.w700,
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          minimumSize: const Size(48, 48),
          shape: RoundedRectangleBorder(borderRadius: radius),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          minimumSize: const Size(48, 48),
          shape: RoundedRectangleBorder(borderRadius: radius),
        ),
      ),
      chipTheme: base.chipTheme.copyWith(
        side: BorderSide(color: scheme.outlineVariant),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(StewardRadii.sm),
        ),
      ),
      dialogTheme: DialogThemeData(
        shape: RoundedRectangleBorder(borderRadius: radius),
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
    );
  }
}

enum StewardStatusTone { positive, neutral, warning, danger }

class StewardStatusPill extends StatelessWidget {
  const StewardStatusPill({required this.label, required this.tone, super.key});

  final String label;
  final StewardStatusTone tone;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final colors = switch (tone) {
      StewardStatusTone.positive => (
        scheme.tertiaryContainer,
        scheme.onTertiaryContainer,
      ),
      StewardStatusTone.warning => (
        scheme.secondaryContainer,
        scheme.onSecondaryContainer,
      ),
      StewardStatusTone.danger => (
        scheme.errorContainer,
        scheme.onErrorContainer,
      ),
      StewardStatusTone.neutral => (
        scheme.surfaceContainerHighest,
        scheme.onSurfaceVariant,
      ),
    };
    final reduceMotion =
        MediaQuery.maybeOf(context)?.disableAnimations ?? false;
    return AnimatedContainer(
      duration: reduceMotion
          ? Duration.zero
          : const Duration(milliseconds: 200),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
      decoration: BoxDecoration(
        color: colors.$1,
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(_icon, size: 16, color: colors.$2),
          const SizedBox(width: 6),
          Flexible(
            child: Text(
              label,
              overflow: TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.labelLarge?.copyWith(
                color: colors.$2,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
    );
  }

  IconData get _icon => switch (tone) {
    StewardStatusTone.positive => Icons.check_circle_outline,
    StewardStatusTone.warning => Icons.sync_problem_outlined,
    StewardStatusTone.danger => Icons.gpp_bad_outlined,
    StewardStatusTone.neutral => Icons.info_outline,
  };
}
