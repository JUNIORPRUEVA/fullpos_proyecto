import 'package:flutter/material.dart';

/// Página de lista de créditos
class CreditsListPage extends StatelessWidget {
  const CreditsListPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey.shade50,
      appBar: AppBar(
        backgroundColor: Colors.blue.shade600,
        title: const Text('Créditos'),
        actions: [
          IconButton(
            icon: const Icon(Icons.filter_list),
            onPressed: () {},
            tooltip: 'Filtros',
          ),
          IconButton(
            icon: const Icon(Icons.search),
            onPressed: () {},
            tooltip: 'Buscar',
          ),
        ],
      ),
      body: const Center(
        child: Text('Lista de créditos'),
      ),
    );
  }
}
