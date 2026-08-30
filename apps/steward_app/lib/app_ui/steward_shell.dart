import 'package:flutter/material.dart';

import 'steward_theme.dart';

class StewardShellDestination {
  const StewardShellDestination({
    required this.label,
    required this.icon,
    required this.selectedIcon,
  });

  final String label;
  final IconData icon;
  final IconData selectedIcon;
}

class StewardAdaptiveShell extends StatelessWidget {
  const StewardAdaptiveShell({
    required this.selectedIndex,
    required this.onDestinationSelected,
    required this.destinations,
    required this.pages,
    required this.statusLabel,
    required this.statusTone,
    super.key,
  }) : assert(destinations.length == pages.length);

  final int selectedIndex;
  final ValueChanged<int> onDestinationSelected;
  final List<StewardShellDestination> destinations;
  final List<Widget> pages;
  final String statusLabel;
  final StewardStatusTone statusTone;

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final useRail = constraints.maxWidth >= 920;
      final content = IndexedStack(index: selectedIndex, children: pages);
      if (!useRail) {
        return Scaffold(
          body: content,
          bottomNavigationBar: NavigationBar(
            selectedIndex: selectedIndex,
            onDestinationSelected: onDestinationSelected,
            destinations: [
              for (final destination in destinations)
                NavigationDestination(
                  icon: Icon(destination.icon),
                  selectedIcon: Icon(destination.selectedIcon),
                  label: destination.label,
                ),
            ],
          ),
        );
      }
      final extended = constraints.maxWidth >= 1240;
      return Scaffold(
        body: Row(
          children: [
            SafeArea(
              right: false,
              child: NavigationRail(
                selectedIndex: selectedIndex,
                onDestinationSelected: onDestinationSelected,
                extended: extended,
                minExtendedWidth: 224,
                labelType: extended
                    ? NavigationRailLabelType.none
                    : NavigationRailLabelType.all,
                leading: Padding(
                  padding: const EdgeInsets.fromLTRB(12, 12, 12, 24),
                  child: extended
                      ? const _ExpandedBrand()
                      : const _CompactBrand(),
                ),
                trailing: Expanded(
                  child: Align(
                    alignment: Alignment.bottomCenter,
                    child: Padding(
                      padding: const EdgeInsets.all(12),
                      child: extended
                          ? StewardStatusPill(
                              label: statusLabel,
                              tone: statusTone,
                            )
                          : Tooltip(
                              message: statusLabel,
                              child: Icon(
                                statusTone == StewardStatusTone.positive
                                    ? Icons.cloud_done_outlined
                                    : Icons.cloud_off_outlined,
                              ),
                            ),
                    ),
                  ),
                ),
                destinations: [
                  for (final destination in destinations)
                    NavigationRailDestination(
                      icon: Icon(destination.icon),
                      selectedIcon: Icon(destination.selectedIcon),
                      label: Text(destination.label),
                    ),
                ],
              ),
            ),
            VerticalDivider(
              width: 1,
              color: Theme.of(context).colorScheme.outlineVariant,
            ),
            Expanded(child: content),
          ],
        ),
      );
    },
  );
}

class _CompactBrand extends StatelessWidget {
  const _CompactBrand();

  @override
  Widget build(BuildContext context) => Container(
    width: 48,
    height: 48,
    decoration: BoxDecoration(
      color: Theme.of(context).colorScheme.primary,
      borderRadius: BorderRadius.circular(16),
    ),
    child: Icon(
      Icons.auto_awesome,
      color: Theme.of(context).colorScheme.onPrimary,
    ),
  );
}

class _ExpandedBrand extends StatelessWidget {
  const _ExpandedBrand();

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      const _CompactBrand(),
      const SizedBox(width: 12),
      Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Data Steward', style: Theme.of(context).textTheme.titleMedium),
          Text('多设备智能管家', style: Theme.of(context).textTheme.bodySmall),
        ],
      ),
    ],
  );
}
