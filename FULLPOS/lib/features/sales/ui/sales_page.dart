import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/errors/error_handler.dart';
import '../../../core/errors/app_exception.dart';
import '../../../core/ui/responsive_grid.dart';
import '../../../core/printing/unified_ticket_printer.dart';
import '../../../core/security/scanner_input_controller.dart';
import '../../../core/security/security_config.dart';
import '../../../core/session/session_manager.dart';
import '../../../core/session/ui_preferences.dart';
import '../../cash/data/cash_repository.dart' as cash_repo;
import '../../cash/ui/cash_open_dialog.dart';
import '../../cash/ui/cash_panel_sheet.dart';
import '../../auth/data/auth_repository.dart';
import '../../clients/data/client_model.dart';
import '../../clients/data/clients_repository.dart';
import '../../clients/ui/client_form_dialog.dart';
import '../../products/data/categories_repository.dart';
import '../../products/data/products_repository.dart';
import '../../products/models/category_model.dart';
import '../../products/models/product_model.dart';
import '../../products/ui/widgets/product_thumbnail.dart';
import '../../settings/data/user_model.dart';
import '../../settings/data/printer_settings_repository.dart';
import '../data/ncf_book_model.dart';
import '../data/ncf_repository.dart';
import '../data/sale_item_model.dart';
import '../data/sale_model.dart';
import '../data/sales_repository.dart';
import '../data/temp_cart_repository.dart';
import '../data/tickets_repository.dart';
import 'dialogs/barcode_info_dialog.dart';
import 'dialogs/client_picker_dialog.dart';
import 'dialogs/payment_dialog.dart' as payment;
import 'dialogs/product_filter_dialog.dart';
import 'dialogs/quick_item_dialog.dart';
import 'dialogs/quote_dialog.dart';
import 'dialogs/ticket_rename_dialog.dart';
import 'dialogs/total_discount_dialog.dart';

/// Pantalla principal de POS con múltiples carritos
class SalesPage extends ConsumerStatefulWidget {
  const SalesPage({super.key});

  @override
  ConsumerState<SalesPage> createState() => _SalesPageState();
}

class _SalesPageState extends ConsumerState<SalesPage> {
  static const double _layoutBreakpointWidth = 980;
  static const double _layoutHysteresis = 40;
  // Productos: tarjetas pequeñas y consistentes (no se inflan por resolución).
  // Ajustes visuales del grid de productos (tamaño fijo premium)
  static const double _productCardSize = 132;
  static const double _productTileMaxExtent = 150;
  bool _didInitResponsive = false;
  bool _layoutIsNarrow = false;

  ColorScheme get scheme => Theme.of(context).colorScheme;

  final List<_Cart> _carts = [_Cart(name: 'Ticket 1')];
  int _currentCartIndex = 0;

  final TextEditingController _searchController = TextEditingController();
  final FocusNode _searchFocusNode = FocusNode();
  final FocusNode _clientFocusNode = FocusNode();

  int? _selectedCartItemIndex;

  bool _isAdmin = false;
  UserPermissions _permissions = UserPermissions.cashier();
  bool _keyboardShortcutsEnabled = true;
  bool _canAccessCash = false;
  SecurityConfig? _scannerConfig;
  String? _scannerTerminalId;
  ScannerInputController? _scanner;

  List<ProductModel> _allProducts = [];
  List<ProductModel> _searchResults = [];
  bool _isSearching = false;

  int? _currentSessionId;
  List<NcfBookModel> _availableNcfs = [];
  List<CategoryModel> _categories = [];
  List<ClientModel> _clients = [];
  ProductFilterModel _productFilter = ProductFilterModel();
  String? _selectedCategory;

  _Cart get _currentCart => _carts[_currentCartIndex];

  void _updateResponsive(BoxConstraints constraints) {
    if (!_didInitResponsive) {
      _didInitResponsive = true;
      _layoutIsNarrow = constraints.maxWidth < _layoutBreakpointWidth;
      return;
    }

    final lower = _layoutBreakpointWidth - _layoutHysteresis;
    final upper = _layoutBreakpointWidth + _layoutHysteresis;
    if (constraints.maxWidth < lower) _layoutIsNarrow = true;
    if (constraints.maxWidth > upper) _layoutIsNarrow = false;
  }

  BoxConstraints _ticketPanelConstraints(double width, bool isNarrow) {
    if (isNarrow) {
      final usable = (width - 24).clamp(300.0, 520.0);
      return BoxConstraints(minWidth: usable, maxWidth: usable);
    }

    if (width < 1100) {
      return const BoxConstraints(minWidth: 320, maxWidth: 380);
    }
    if (width < 1350) {
      return const BoxConstraints(minWidth: 360, maxWidth: 440);
    }
    return const BoxConstraints(minWidth: 400, maxWidth: 520);
  }

  @override
  void initState() {
    super.initState();
    _loadAccess();
    _loadInitialData();
    _refreshCashSession();
    _loadScannerConfig();
    RawKeyboard.instance.addListener(_handleScannerKey);
  }

  Future<void> _loadAccess() async {
    final results = await Future.wait([
      AuthRepository.getCurrentPermissions(),
      AuthRepository.isAdmin(),
      UiPreferences.isKeyboardShortcutsEnabled(),
    ]);

    if (!mounted) return;
    final perms = results[0] as UserPermissions;
    final isAdmin = results[1] as bool;
    setState(() {
      _permissions = perms;
      _isAdmin = isAdmin;
      _keyboardShortcutsEnabled = results[2] as bool;
      _canAccessCash = isAdmin || perms.canOpenCash || perms.canCloseCash;
    });
  }

  void _handleScannerKey(RawKeyEvent event) {
    _scanner?.handleKeyEvent(event);
  }

  Future<void> _loadScannerConfig() async {
    final companyId = await SessionManager.companyId() ?? 1;
    final terminalId =
        await SessionManager.terminalId() ??
        await SessionManager.ensureTerminalId();
    final config = await SecurityConfigRepository.load(
      companyId: companyId,
      terminalId: terminalId,
    );

    if (!mounted) return;

    _scanner?.dispose();
    _scanner = config.scannerEnabled
        ? ScannerInputController(
            enabled: true,
            suffix: config.scannerSuffix,
            prefix: config.scannerPrefix,
            timeout: Duration(milliseconds: config.scannerTimeoutMs),
            emitOnTimeout: false,
            onScan: _handleBarcodeScan,
          )
        : null;

    setState(() {
      _scannerConfig = config;
      _scannerTerminalId = terminalId;
    });
  }

  Future<void> _handleBarcodeScan(String raw) async {
    final code = raw.trim();
    if (code.isEmpty) return;

    final repo = ProductsRepository();
    ProductModel? product = await ErrorHandler.instance.runSafe<ProductModel?>(
      () => repo.getByCode(code),
      context: context,
      onRetry: () => _handleBarcodeScan(code),
      module: 'sales/scan/code',
    );

    if (product == null && code.toUpperCase() != code) {
      product = await ErrorHandler.instance.runSafe<ProductModel?>(
        () => repo.getByCode(code.toUpperCase()),
        context: context,
        onRetry: () => _handleBarcodeScan(code),
        module: 'sales/scan/code_upper',
      );
    }

    if (product == null) {
      final results = await ErrorHandler.instance.runSafe<List<ProductModel>>(
        () => repo.search(code),
        context: context,
        onRetry: () => _handleBarcodeScan(code),
        module: 'sales/scan/search',
      );
      if (results != null && results.length == 1) {
        product = results.first;
      }
    }

    if (!mounted) return;

    if (product == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('No se encontro producto con codigo: $code'),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    await _addProductToCart(product);

    if (_searchController.text.isNotEmpty) {
      _searchController.clear();
      _searchProducts('');
    }
  }

  @override
  void dispose() {
    _saveAllCartsToDatabase();
    _searchController.dispose();
    _searchFocusNode.dispose();
    _clientFocusNode.dispose();
    RawKeyboard.instance.removeListener(_handleScannerKey);
    _scanner?.dispose();
    super.dispose();
  }

  Future<void> _loadInitialData() async {
    setState(() => _isSearching = true);

    final products = await ProductsRepository().getAll();
    final categories = await CategoriesRepository().getAll();
    final clients = await ClientsRepository.getAll();
    final dbTickets = await TicketsRepository().listTickets();

    // Convertir tickets de BD a _Cart objects
    final loadedCarts = <_Cart>[];
    for (final ticketModel in dbTickets) {
      final cartItems = await TicketsRepository().getTicketItems(
        ticketModel.id!,
      );
      final cart = _Cart(name: ticketModel.ticketName)
        ..ticketId = ticketModel.id
        ..itbisEnabled = ticketModel.itbisEnabled
        ..itbisRate = ticketModel.itbisRate
        ..discount = ticketModel.discountTotal;

      // Convertir items de BD a SaleItemModel
      for (final itemModel in cartItems) {
        cart.items.add(
          SaleItemModel(
            id: itemModel.id,
            saleId: 0,
            productId: itemModel.productId,
            productCodeSnapshot: itemModel.productCodeSnapshot,
            productNameSnapshot: itemModel.productNameSnapshot,
            qty: itemModel.qty,
            unitPrice: itemModel.price,
            discountLine: itemModel.discountLine,
            purchasePriceSnapshot: itemModel.cost,
            totalLine: itemModel.totalLine,
            createdAtMs: 0,
          ),
        );
      }

      loadedCarts.add(cart);
    }

    // Cargar carritos temporales
    final tempCartRepo = TempCartRepository();
    final tempCarts = await tempCartRepo.getAllCarts();
    for (final cartMap in tempCarts) {
      final cart = _Cart(name: cartMap['name'] as String)
        ..tempCartId = cartMap['id'] as int
        ..discount = (cartMap['discount'] as num).toDouble()
        ..itbisEnabled = (cartMap['itbis_enabled'] as int) == 1
        ..itbisRate = (cartMap['itbis_rate'] as num).toDouble()
        ..fiscalEnabled = (cartMap['fiscal_enabled'] as int) == 1
        ..discountTotalType = cartMap['discount_total_type'] as String?
        ..discountTotalValue = (cartMap['discount_total_value'] as num?)
            ?.toDouble();

      // Cargar cliente si existe
      final clientId = cartMap['client_id'] as int?;
      if (clientId != null) {
        final client = clients.where((c) => c.id == clientId).firstOrNull;
        if (client != null) cart.selectedClient = client;
      }

      // Cargar items del carrito
      final cartItems = await tempCartRepo.getCartItems(cart.tempCartId!);
      cart.items.addAll(cartItems);

      loadedCarts.add(cart);
    }

    setState(() {
      _allProducts = products;
      _searchResults = products;
      _categories = categories;
      _clients = clients;
      // Si hay tickets o carritos cargados, usarlos; si no, comenzar con el carrito vacío
      if (loadedCarts.isNotEmpty) {
        _carts.clear();
        _carts.addAll(loadedCarts);
        _currentCartIndex = 0;
      }
      _isSearching = false;
    });
  }

  Future<void> _refreshCashSession() async {
    final session = await cash_repo.CashRepository.getOpenSession();
    setState(() => _currentSessionId = session?.id);
  }

  /// Guarda todos los carritos temporales en la base de datos
  Future<void> _saveAllCartsToDatabase() async {
    final tempCartRepo = TempCartRepository();

    for (final cart in _carts) {
      // Solo guardar carritos que no sean tickets pendientes y tengan items
      if (cart.ticketId == null && cart.items.isNotEmpty) {
        try {
          await tempCartRepo.saveCart(
            id: cart.tempCartId,
            name: cart.name,
            userId: null,
            clientId: cart.selectedClient?.id,
            discount: cart.discount,
            itbisEnabled: cart.itbisEnabled,
            itbisRate: cart.itbisRate,
            fiscalEnabled: cart.fiscalEnabled,
            discountTotalType: cart.discountTotalType,
            discountTotalValue: cart.discountTotalValue,
            items: cart.items,
          );
        } catch (e) {
          debugPrint('Error guardando carrito temporal: $e');
        }
      }
    }
  }

  /// Elimina el carrito temporal de la base de datos
  Future<void> _deleteCurrentCartFromDatabase() async {
    if (_currentCart.tempCartId != null) {
      try {
        await TempCartRepository().deleteCart(_currentCart.tempCartId!);
      } catch (e) {
        debugPrint('Error eliminando carrito temporal: $e');
      }
    }
  }

  Future<void> _loadAvailableNcfs() async {
    final all = await NcfRepository.getAll();
    final available = all.where((ncf) => ncf.isAvailable).toList();
    setState(() {
      _availableNcfs = available;

      // Asegura que el dropdown siempre tenga un value que exista en los items
      if (_currentCart.fiscalEnabled) {
        final selected = _currentCart.selectedNcf;
        if (selected?.id != null) {
          final match = available.where((b) => b.id == selected!.id).toList();
          _currentCart.selectedNcf = match.isNotEmpty
              ? match.first
              : (available.isNotEmpty ? available.first : null);
        } else if (selected != null) {
          final match = available
              .where(
                (b) =>
                    b.type == selected.type &&
                    b.series == selected.series &&
                    b.fromN == selected.fromN &&
                    b.toN == selected.toN,
              )
              .toList();
          _currentCart.selectedNcf = match.isNotEmpty
              ? match.first
              : (available.isNotEmpty ? available.first : null);
        } else {
          _currentCart.selectedNcf = available.isNotEmpty
              ? available.first
              : null;
        }
      }
    });
  }

  // Ajusta el stock localmente tras completar una venta para reflejar el inventario actualizado
  void _applyStockAdjustments(List<SaleItemModel> items) {
    if (items.isEmpty) return;

    final Map<int, double> deltas = {};
    for (final item in items) {
      final productId = item.productId;
      if (productId != null) {
        deltas.update(
          productId,
          (value) => value + item.qty,
          ifAbsent: () => item.qty,
        );
      }
    }

    if (deltas.isEmpty) return;

    double _newStock(double current, double delta) {
      final updated = current - delta;
      return updated < 0 ? 0 : updated;
    }

    setState(() {
      _allProducts = _allProducts
          .map(
            (p) => deltas.containsKey(p.id)
                ? p.copyWith(stock: _newStock(p.stock, deltas[p.id]!))
                : p,
          )
          .toList();

      _searchResults = _searchResults
          .map(
            (p) => deltas.containsKey(p.id)
                ? p.copyWith(stock: _newStock(p.stock, deltas[p.id]!))
                : p,
          )
          .toList();
    });
  }

  List<ProductModel> _filteredProducts() {
    final source = _searchController.text.trim().isEmpty
        ? _allProducts
        : _searchResults;

    final filtered = source.where((p) {
      if (_selectedCategory != null && _selectedCategory != 'Todos') {
        final match = _categories.firstWhere(
          (c) => c.name == _selectedCategory,
          orElse: () => CategoryModel(
            id: -1,
            name: '',
            isActive: true,
            createdAtMs: 0,
            updatedAtMs: 0,
          ),
        );
        if (match.id != null && p.categoryId != match.id) return false;
      }
      if (_productFilter.onlyWithStock && p.stock <= 0) return false;
      if (_productFilter.minPrice != null &&
          p.salePrice < _productFilter.minPrice!) {
        return false;
      }
      if (_productFilter.maxPrice != null &&
          p.salePrice > _productFilter.maxPrice!) {
        return false;
      }
      return true;
    }).toList();

    switch (_productFilter.sortBy) {
      case ProductSortBy.nameAsc:
        filtered.sort((a, b) => a.name.compareTo(b.name));
        break;
      case ProductSortBy.nameDesc:
        filtered.sort((a, b) => b.name.compareTo(a.name));
        break;
      case ProductSortBy.priceAsc:
        filtered.sort((a, b) => a.salePrice.compareTo(b.salePrice));
        break;
      case ProductSortBy.priceDesc:
        filtered.sort((a, b) => b.salePrice.compareTo(a.salePrice));
        break;
      case ProductSortBy.stockAsc:
        filtered.sort((a, b) => a.stock.compareTo(b.stock));
        break;
      case ProductSortBy.stockDesc:
        filtered.sort((a, b) => b.stock.compareTo(a.stock));
        break;
    }

    return filtered;
  }

  Future<void> _searchProducts(String query) async {
    setState(() => _isSearching = true);
    final repo = ProductsRepository();
    final trimmed = query.trim();
    final results = trimmed.isEmpty
        ? await repo.getAll()
        : await repo.search(trimmed);

    if (!mounted) return;

    setState(() {
      _searchResults = results;
      if (trimmed.isEmpty) _allProducts = results;
      _isSearching = false;
    });
  }

  void _onCategorySelected(String? categoryName) {
    setState(
      () => _selectedCategory = categoryName == 'Todos' ? null : categoryName,
    );
  }

  Future<void> _openFilterDialog() async {
    final result = await showDialog<ProductFilterModel>(
      context: context,
      builder: (context) => ProductFilterDialog(
        initialFilter: _productFilter,
        categories: _categories
            .map((c) => {'id': c.id, 'name': c.name})
            .toList(),
      ),
    );

    if (result != null) {
      setState(() => _productFilter = result);
    }
  }

  Future<void> _showClientPicker() async {
    final result = await showDialog<ClientModel>(
      context: context,
      builder: (context) => ClientPickerDialog(clients: _clients),
    );

    if (result != null) {
      setState(() {
        _currentCart.selectedClient = result;
        _currentCart.name = result.nombre;
      });
      if (_currentCart.ticketId != null) {
        final ticketId = _currentCart.ticketId!;
        await ErrorHandler.instance.runSafe<void>(
          () => TicketsRepository().updateTicketName(ticketId, result.nombre),
          context: context,
          onRetry: () => ErrorHandler.instance.runSafe<void>(
            () => TicketsRepository().updateTicketName(ticketId, result.nombre),
            context: context,
            module: 'sales/ticket_name',
          ),
          module: 'sales/ticket_name',
        );
      }
    }
  }

  Future<void> _showQuickItemDialog() async {
    final result = await showDialog<SaleItemModel>(
      context: context,
      builder: (context) => const QuickItemDialog(),
    );

    if (result != null) {
      setState(() => _currentCart.items.add(result));
    }
  }

  Future<void> _showTotalDiscountDialog() async {
    if (_currentCart.items.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Agrega productos antes de aplicar descuento'),
          backgroundColor: Colors.orange,
        ),
      );
      return;
    }

    final currentDiscount =
        _currentCart.discountTotalValue != null &&
            _currentCart.discountTotalValue! > 0
        ? DiscountResult(
            type: _currentCart.discountTotalType == 'percent'
                ? DiscountType.percent
                : DiscountType.amount,
            value: _currentCart.discountTotalValue!,
          )
        : null;

    final result = await showDialog<dynamic>(
      context: context,
      builder: (context) => TotalDiscountDialog(
        subtotal: _currentCart.calculateSubtotal(),
        itbisRate: _currentCart.itbisRate,
        currentDiscount: currentDiscount,
      ),
    );

    if (result == 'remove') {
      setState(() {
        _currentCart.discountTotalType = null;
        _currentCart.discountTotalValue = null;
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Descuento eliminado'),
          backgroundColor: Colors.green,
        ),
      );
    } else if (result is DiscountResult) {
      setState(() {
        _currentCart.discountTotalType = result.type == DiscountType.percent
            ? 'percent'
            : 'amount';
        _currentCart.discountTotalValue = result.value;
      });
      final discountLabel = result.type == DiscountType.percent
          ? 'Descuento aplicado: ${result.value.toStringAsFixed(1)}%'
          : 'Descuento aplicado: RD\$ ${result.value.toStringAsFixed(2)}';
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(discountLabel), backgroundColor: Colors.green),
      );
    }
  }

  Future<void> _addNewTicket() async {
    final defaultName = 'Ticket ${_carts.length + 1}';
    final result = await showDialog<String>(
      context: context,
      builder: (context) =>
          TicketRenameDialog(currentName: defaultName, isNewTicket: true),
    );

    final ticketName = (result != null && result.trim().isNotEmpty)
        ? result.trim()
        : defaultName;

    setState(() {
      _carts.add(_Cart(name: ticketName));
      _currentCartIndex = _carts.length - 1;
    });
  }

  void _removeClient() {
    final ticketIndex = _carts.indexOf(_currentCart);
    setState(() {
      _currentCart.selectedClient = null;
      _currentCart.name = 'Ticket ${ticketIndex + 1}';
    });
  }

  Future<void> _addProductToCart(ProductModel product) async {
    final qtyInCart = _currentCart.getQuantityForProduct(product.id ?? -1);
    final effectiveStock = product.stock - qtyInCart;
    if (effectiveStock <= 0) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Producto sin stock disponible'),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    setState(() => _currentCart.addProduct(product));
  }

  void _incrementCartItemQty(SaleItemModel item, int index) async {
    if (item.productId == null) {
      setState(() => _currentCart.updateQuantity(index, item.qty + 1));
      return;
    }

    final repo = ProductsRepository();
    final product = await ErrorHandler.instance.runSafe<ProductModel?>(
      () => repo.getById(item.productId!),
      context: context,
      onRetry: () => _incrementCartItemQty(item, index),
      module: 'sales/product_get',
    );
    if (product == null) return;
    final available =
        product.stock - _currentCart.getQuantityForProduct(item.productId!);
    if (available <= 0) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Stock insuficiente'),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    setState(() => _currentCart.updateQuantity(index, item.qty + 1));
  }

  void _showEditItemDialog(SaleItemModel item, int index) {
    final qtyController = TextEditingController(
      text: item.qty.toStringAsFixed(0),
    );
    final discountController = TextEditingController(
      text: item.discountLine.toStringAsFixed(2),
    );
    String discountMode = 'amount';

    double _computeBaseSubtotal() {
      final qty = double.tryParse(qtyController.text) ?? item.qty;
      return qty * item.unitPrice;
    }

    double _computeDiscountAmount() {
      final base = _computeBaseSubtotal();
      final raw = double.tryParse(discountController.text) ?? 0.0;
      if (discountMode == 'percent') {
        final pct = raw.clamp(0.0, 100.0);
        return base * (pct / 100);
      }
      return raw.clamp(0.0, base);
    }

    showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setStateDialog) {
          final subtotal = _computeBaseSubtotal();
          final discountAmount = _computeDiscountAmount();
          final total = (subtotal - discountAmount).clamp(0.0, double.infinity);

          return AlertDialog(
            title: Text(item.productNameSnapshot),
            content: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Código: ${item.productCodeSnapshot}',
                    style: TextStyle(color: Colors.grey.shade600, fontSize: 13),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Precio unitario: ${item.unitPrice.toStringAsFixed(2)}',
                    style: TextStyle(color: Colors.grey.shade600, fontSize: 13),
                  ),
                  const SizedBox(height: 16),
                  TextField(
                    controller: qtyController,
                    decoration: const InputDecoration(
                      labelText: 'Cantidad',
                      prefixIcon: Icon(Icons.numbers),
                      border: OutlineInputBorder(),
                    ),
                    keyboardType: const TextInputType.numberWithOptions(
                      decimal: true,
                    ),
                    onChanged: (_) => setStateDialog(() {}),
                  ),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 8,
                    children: [
                      ChoiceChip(
                        label: const Text('Monto'),
                        selected: discountMode == 'amount',
                        onSelected: (_) =>
                            setStateDialog(() => discountMode = 'amount'),
                      ),
                      ChoiceChip(
                        label: const Text('Porcentaje'),
                        selected: discountMode == 'percent',
                        onSelected: (_) =>
                            setStateDialog(() => discountMode = 'percent'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: discountController,
                    decoration: InputDecoration(
                      labelText: discountMode == 'percent'
                          ? 'Descuento (%)'
                          : 'Descuento (RD\$)',
                      prefixIcon: const Icon(Icons.local_offer),
                      border: const OutlineInputBorder(),
                      helperText: discountMode == 'percent'
                          ? 'Aplica % sobre el subtotal de este producto'
                          : 'Monto fijo a descontar',
                    ),
                    keyboardType: const TextInputType.numberWithOptions(
                      decimal: true,
                    ),
                    onChanged: (_) => setStateDialog(() {}),
                  ),
                  const SizedBox(height: 16),
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: scheme.primary.withOpacity(0.08),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Column(
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Text(
                              'Subtotal:',
                              style: TextStyle(fontSize: 13),
                            ),
                            Text(
                              subtotal.toStringAsFixed(2),
                              style: const TextStyle(
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ],
                        ),
                        SizedBox(height: 4),
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Text(
                              discountMode == 'percent'
                                  ? 'Descuento (${(double.tryParse(discountController.text) ?? 0).clamp(0.0, 100.0).toStringAsFixed(1)}%)'
                                  : 'Descuento:',
                              style: const TextStyle(fontSize: 13),
                            ),
                            Text(
                              '-${discountAmount.toStringAsFixed(2)}',
                              style: TextStyle(
                                fontSize: 13,
                                fontWeight: FontWeight.w600,
                                color: Colors.red.shade700,
                              ),
                            ),
                          ],
                        ),
                        SizedBox(height: 4),
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            const Text(
                              'Total:',
                              style: TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            Text(
                              total.toStringAsFixed(2),
                            style: TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                              color: scheme.primary,
                            ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('Cancelar'),
              ),
              ElevatedButton.icon(
                onPressed: () {
                  final newQty =
                      double.tryParse(qtyController.text) ?? item.qty;
                  final discountToApply = _computeDiscountAmount();

                  if (newQty <= 0) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('La cantidad debe ser mayor a 0'),
                        backgroundColor: Colors.red,
                      ),
                    );
                    return;
                  }

                  setState(() {
                    _currentCart.items[index] = item.copyWith(
                      qty: newQty,
                      discountLine: discountToApply,
                    );
                  });
                  Navigator.pop(context);
                },
                icon: const Icon(Icons.check),
                label: const Text('Aplicar'),
                style: ElevatedButton.styleFrom(backgroundColor: scheme.primary),
              ),
            ],
          );
        },
      ),
    );
  }

  Future<void> _processPayment(String kind) async {
    if (_currentCart.items.isEmpty) return;

    if (_currentCart.fiscalEnabled && _availableNcfs.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'No hay NCF disponibles. Hable con Administración para agregarlo.',
          ),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    if (_currentCart.fiscalEnabled && _currentCart.selectedNcf == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Seleccione un Comprobante Fiscal (NCF)'),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    // Importante: usar las funciones del carrito como fuente única.
    // Evita doble descuento (bug: totales guardados/impresos en 0).
    final totalDiscount = _currentCart.calculateTotalDiscountsCombined();
    final subtotalAfterDiscount = _currentCart.calculateSubtotalAfterDiscount();
    final itbisAmount = _currentCart.calculateItbis();
    final total = _currentCart.calculateTotal();
    final paymentResult = await showDialog<Map<String, dynamic>>(
      context: context,
      builder: (context) => payment.PaymentDialog(
        total: total,
        selectedClient: _currentCart.selectedClient,
        onSelectClient: _showClientPicker,
      ),
    );

    if (paymentResult == null) return;

    final method = paymentResult['method'] as payment.PaymentMethod;
    final receivedAmount =
        (paymentResult['received'] as num?)?.toDouble() ?? total;
    final changeAmount = (paymentResult['change'] as num?)?.toDouble() ?? 0.0;
    final shouldPrint = paymentResult['printTicket'] == true;

    final localCode = await SalesRepository.generateNextLocalCode(kind);
    String? ncfFull;
    String? ncfType;
    if (_currentCart.fiscalEnabled && _currentCart.selectedNcf != null) {
      final selected = _currentCart.selectedNcf!;
      ncfType = selected.type;

      // Consumir el NCF del talonario seleccionado (evita consumir otro libro del mismo tipo)
      if (selected.id != null) {
        ncfFull = await NcfRepository.consumeNextForBook(selected.id!);
      } else {
        ncfFull = await NcfRepository.consumeNext(selected.type);
      }

      if (ncfFull == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text(
              'No hay NCF disponibles para el talonario seleccionado',
            ),
            backgroundColor: Colors.red,
          ),
        );
        return;
      }
    }

    final paymentMethodStr = switch (method) {
      payment.PaymentMethod.cash => PaymentMethod.cash,
      payment.PaymentMethod.card => PaymentMethod.card,
      payment.PaymentMethod.transfer => PaymentMethod.transfer,
      payment.PaymentMethod.mixed => PaymentMethod.mixed,
      payment.PaymentMethod.credit => PaymentMethod.mixed,
    };

    final productsRepo = ProductsRepository();
    final List<SaleItemModel> itemsPayload = [];

    for (final item in _currentCart.items) {
      var enriched = item;

      // Refresca datos del producto para guardar código, nombre, precio y costo actuales
      if (item.productId != null) {
        final product = await productsRepo.getById(item.productId!);
        if (product != null) {
          enriched = enriched.copyWith(
            productCodeSnapshot: enriched.productCodeSnapshot.isNotEmpty
                ? enriched.productCodeSnapshot
                : product.code,
            productNameSnapshot: enriched.productNameSnapshot.isNotEmpty
                ? enriched.productNameSnapshot
                : product.name,
            unitPrice: enriched.unitPrice > 0
                ? enriched.unitPrice
                : product.salePrice,
            purchasePriceSnapshot: enriched.purchasePriceSnapshot > 0
                ? enriched.purchasePriceSnapshot
                : product.purchasePrice,
          );
        }
      }

      final totalLine =
          (enriched.qty * enriched.unitPrice) - enriched.discountLine;
      itemsPayload.add(enriched.copyWith(totalLine: totalLine));
    }

    int saleId;
    try {
      saleId = await SalesRepository.createSale(
        localCode: localCode,
        kind: kind,
        items: itemsPayload,
        itbisEnabled: _currentCart.itbisEnabled,
        itbisRate: _currentCart.itbisRate,
        discountTotal: totalDiscount,
        subtotalOverride: subtotalAfterDiscount,
        itbisAmountOverride: itbisAmount,
        totalOverride: total,
        paymentMethod: paymentMethodStr,
        sessionId: _currentSessionId,
        customerId: _currentCart.selectedClient?.id,
        customerName: _currentCart.selectedClient?.nombre,
        customerPhone: _currentCart.selectedClient?.telefono,
        ncfFull: ncfFull,
        ncfType: ncfType,
        fiscalEnabled: _currentCart.fiscalEnabled,
        paidAmount: receivedAmount,
        changeAmount: changeAmount > 0 ? changeAmount : 0,
      );
    } on AppException catch (e, st) {
      if (e.code != 'stock_negative') {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          module: 'sales',
        );
        return;
      }

      final proceed = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: const Text('Stock insuficiente'),
          content: Text(e.messageUser),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('CANCELAR'),
            ),
            ElevatedButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('CONTINUAR'),
            ),
          ],
        ),
      );

      if (proceed != true) return;

      final retry = await ErrorHandler.instance.runSafe<int>(
        () => SalesRepository.createSale(
          localCode: localCode,
          kind: kind,
          items: itemsPayload,
          allowNegativeStock: true,
          itbisEnabled: _currentCart.itbisEnabled,
          itbisRate: _currentCart.itbisRate,
          discountTotal: totalDiscount,
          subtotalOverride: subtotalAfterDiscount,
          itbisAmountOverride: itbisAmount,
          totalOverride: total,
          paymentMethod: paymentMethodStr,
          sessionId: _currentSessionId,
          customerId: _currentCart.selectedClient?.id,
          customerName: _currentCart.selectedClient?.nombre,
          customerPhone: _currentCart.selectedClient?.telefono,
          ncfFull: ncfFull,
          ncfType: ncfType,
          fiscalEnabled: _currentCart.fiscalEnabled,
          paidAmount: receivedAmount,
          changeAmount: changeAmount > 0 ? changeAmount : 0,
        ),
        context: context,
        module: 'sales',
      );
      if (retry == null) return;
      saleId = retry;
    } catch (e, st) {
      await ErrorHandler.instance.handle(
        e,
        stackTrace: st,
        context: context,
        module: 'sales',
      );
      return;
    }

    _applyStockAdjustments(itemsPayload);

    if (shouldPrint) {
      try {
        final sale = await SalesRepository.getSaleById(saleId);
        final items = await SalesRepository.getItemsBySaleId(saleId);
        if (sale != null) {
          final settings = await PrinterSettingsRepository.getOrCreate();
          if (settings.selectedPrinterName != null &&
              settings.selectedPrinterName!.isNotEmpty) {
            final cashierName = await SessionManager.displayName() ?? 'Cajero';
            await UnifiedTicketPrinter.printSaleTicket(
              sale: sale,
              items: items,
              cashierName: cashierName,
            );
          }
        }
      } catch (e) {
        debugPrint('Error al imprimir ticket: $e');
      }
    }

    // ✅ LIMPIEZA: Marcar como completado, eliminar de lista, y seleccionar siguiente ticket
    // Eliminar carrito temporal si existe
    await _deleteCurrentCartFromDatabase();

    setState(() {
      _currentCart.isCompleted = true;

      // Eliminar el ticket completado de la lista
      _carts.removeAt(_currentCartIndex);

      // Seleccionar el siguiente ticket o crear uno nuevo
      if (_carts.isNotEmpty) {
        // Si hay tickets pendientes, seleccionar el primero disponible
        // (la UI mostrará tickets pendientes solamente)
        _currentCartIndex = 0;
      } else {
        // Si no hay más tickets, crear uno nuevo
        _carts.add(_Cart(name: 'Ticket 1'));
        _currentCartIndex = 0;
      }

      _selectedCartItemIndex = null;
    });

    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text(
          '✔ Venta completada correctamente',
          style: TextStyle(fontSize: 14, fontWeight: FontWeight.w500),
        ),
        backgroundColor: Colors.green,
        duration: Duration(seconds: 2),
      ),
    );
  }

  Future<void> _saveAsQuote() async {
    final result = await showDialog<QuoteDialogResult>(
      context: context,
      builder: (context) => QuoteDialog(
        items: _currentCart.items,
        selectedClient: _currentCart.selectedClient,
        itbisEnabled: _currentCart.itbisEnabled,
        itbisRate: _currentCart.itbisRate,
        discountTotal:
            _currentCart.discount + _currentCart.calculateTotalDiscount(),
        ticketName: _currentCart.name,
      ),
    );

    if (result?.saved == true && result!.clearCart) {
      // Eliminar carrito temporal si existe
      await _deleteCurrentCartFromDatabase();

      setState(() {
        _currentCart.clear();
        _selectedCartItemIndex = null;
      });
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Cotización guardada'),
          backgroundColor: Colors.green,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Shortcuts(
      shortcuts: _keyboardShortcutsEnabled
          ? {
              LogicalKeySet(LogicalKeyboardKey.f2):
                  const FocusSearchProductIntent(),
              LogicalKeySet(LogicalKeyboardKey.f3):
                  const FocusSearchClientIntent(),
              LogicalKeySet(LogicalKeyboardKey.f4): const NewClientIntent(),
              LogicalKeySet(LogicalKeyboardKey.f7): const ApplyDiscountIntent(),
              LogicalKeySet(LogicalKeyboardKey.f8): const OpenPaymentIntent(),
              LogicalKeySet(LogicalKeyboardKey.f9): const OpenPaymentIntent(),
              LogicalKeySet(LogicalKeyboardKey.f12): const FinalizeSaleIntent(),
              LogicalKeySet(
                LogicalKeyboardKey.control,
                LogicalKeyboardKey.backspace,
              ): const DeleteSelectedItemIntent(),
              LogicalKeySet(LogicalKeyboardKey.add):
                  const IncreaseQuantityIntent(),
              LogicalKeySet(LogicalKeyboardKey.equal, LogicalKeyboardKey.shift):
                  const IncreaseQuantityIntent(),
              LogicalKeySet(LogicalKeyboardKey.minus):
                  const DecreaseQuantityIntent(),
            }
          : const {},
      child: Actions(
        actions: {
          FocusSearchProductIntent: CallbackAction<FocusSearchProductIntent>(
            onInvoke: (_) {
              _searchFocusNode.requestFocus();
              return null;
            },
          ),
          FocusSearchClientIntent: CallbackAction<FocusSearchClientIntent>(
            onInvoke: (_) {
              _showClientPicker();
              return null;
            },
          ),
          NewClientIntent: CallbackAction<NewClientIntent>(
            onInvoke: (_) async {
              final result = await showDialog<ClientModel>(
                context: context,
                builder: (context) => const ClientFormDialog(),
              );
              if (result != null) {
                setState(() {
                  _clients.add(result);
                  _currentCart.selectedClient = result;
                });
              }
              return null;
            },
          ),
          ApplyDiscountIntent: CallbackAction<ApplyDiscountIntent>(
            onInvoke: (_) {
              if (_selectedCartItemIndex != null &&
                  _selectedCartItemIndex! < _currentCart.items.length) {
                _showEditItemDialog(
                  _currentCart.items[_selectedCartItemIndex!],
                  _selectedCartItemIndex!,
                );
              }
              return null;
            },
          ),
          OpenPaymentIntent: CallbackAction<OpenPaymentIntent>(
            onInvoke: (_) {
              if (_currentCart.items.isNotEmpty) {
                _processPayment(SaleKind.invoice);
              }
              return null;
            },
          ),
          FinalizeSaleIntent: CallbackAction<FinalizeSaleIntent>(
            onInvoke: (_) {
              if (_currentCart.items.isNotEmpty) {
                _processPayment(SaleKind.invoice);
              }
              return null;
            },
          ),
          DeleteSelectedItemIntent: CallbackAction<DeleteSelectedItemIntent>(
            onInvoke: (_) {
              if (_selectedCartItemIndex != null &&
                  _selectedCartItemIndex! < _currentCart.items.length) {
                setState(() {
                  _currentCart.removeItem(_selectedCartItemIndex!);
                  _selectedCartItemIndex = null;
                });
              }
              return null;
            },
          ),
          IncreaseQuantityIntent: CallbackAction<IncreaseQuantityIntent>(
            onInvoke: (_) {
              if (_selectedCartItemIndex != null &&
                  _selectedCartItemIndex! < _currentCart.items.length) {
                setState(() {
                  final item = _currentCart.items[_selectedCartItemIndex!];
                  _currentCart.updateQuantity(
                    _selectedCartItemIndex!,
                    item.qty + 1,
                  );
                });
              }
              return null;
            },
          ),
          DecreaseQuantityIntent: CallbackAction<DecreaseQuantityIntent>(
            onInvoke: (_) {
              if (_selectedCartItemIndex != null &&
                  _selectedCartItemIndex! < _currentCart.items.length) {
                setState(() {
                  final item = _currentCart.items[_selectedCartItemIndex!];
                  if (item.qty > 1) {
                    _currentCart.updateQuantity(
                      _selectedCartItemIndex!,
                      item.qty - 1,
                    );
                  }
                });
              }
              return null;
            },
          ),
        },
        child: Focus(
          autofocus: true,
          child: Scaffold(
            backgroundColor: Theme.of(context).scaffoldBackgroundColor,
            body: Stack(
              children: [
                LayoutBuilder(
                  builder: (context, constraints) {
                    _updateResponsive(constraints);
                    final isNarrow = _layoutIsNarrow;
                    final ticketPanelConstraints =
                        _ticketPanelConstraints(constraints.maxWidth, isNarrow);
                    final panelMargin =
                        constraints.maxWidth < 1150 ? 8.0 : 10.0;
                    final scheme = Theme.of(context).colorScheme;
                    return Flex(
                      direction: isNarrow ? Axis.vertical : Axis.horizontal,
                      children: [
                        Expanded(
                          flex: 7,
                          child: Column(
                            children: [
                              Container(
                                padding: const EdgeInsets.all(16),
                                decoration: BoxDecoration(
                                  color: scheme.surface,
                                  boxShadow: [
                                    BoxShadow(
                                      color: Colors.black.withOpacity(0.2),
                                      blurRadius: 10,
                                      offset: const Offset(0, 6),
                                    ),
                                  ],
                                ),
                                child: Column(children: [_build3DControlBar()]),
                              ),
                              Expanded(
                                child: Container(
                                  margin: const EdgeInsets.only(top: 8),
                                  decoration: BoxDecoration(
                                    color: scheme.surface,
                                    borderRadius: BorderRadius.circular(16),
                                    boxShadow: [
                                      BoxShadow(
                                        color: Colors.black.withOpacity(0.25),
                                        blurRadius: 16,
                                        offset: const Offset(0, 8),
                                      ),
                                      BoxShadow(
                                        color: scheme.primary.withOpacity(0.08),
                                        blurRadius: 10,
                                        offset: const Offset(-2, -2),
                                        spreadRadius: -1,
                                      ),
                                    ],
                                  ),
                                  clipBehavior: Clip.antiAlias,
                                  child: Stack(
                                    children: [
                                      _isSearching
                                          ? const Center(
                                              child:
                                                  CircularProgressIndicator(),
                                            )
                                          : _filteredProducts().isEmpty
                                          ? Center(
                                              child: Column(
                                                mainAxisAlignment:
                                                    MainAxisAlignment.center,
                                                children: [
                                                  Icon(
                                                    Icons.inventory_2_outlined,
                                                    size: 80,
                                                    color: Colors.grey[300],
                                                  ),
                                                  const SizedBox(height: 16),
                                                  Text(
                                                    'No hay productos disponibles',
                                                    style: TextStyle(
                                                      color: Colors.grey[600],
                                                      fontSize: 18,
                                                      fontWeight:
                                                          FontWeight.w500,
                                                    ),
                                                  ),
                                                  const SizedBox(height: 8),
                                                  Text(
                                                    'Intenta buscar con otro término',
                                                    style: TextStyle(
                                                      color: Colors.grey[400],
                                                      fontSize: 14,
                                                    ),
                                                  ),
                                                ],
                                              ),
                                            )
                                          : Padding(
                                              padding: const EdgeInsets.only(
                                                left: 14,
                                                right: 14,
                                                top: 16,
                                                bottom: 72,
                                              ),
                                              child: LayoutBuilder(
                                                builder: (context, constraints) {
                                                  final products =
                                                      _filteredProducts();
                                                  final maxExtent =
                                                      stableMaxCrossAxisExtent(
                                                        availableWidth:
                                                            constraints
                                                                .maxWidth,
                                                        desiredMaxExtent:
                                                            _productTileMaxExtent,
                                                        spacing: 12,
                                                        minExtent:
                                                            _productTileMaxExtent,
                                                      );

                                                  return GridView.builder(
                                                    gridDelegate:
                                                        SliverGridDelegateWithMaxCrossAxisExtent(
                                                          maxCrossAxisExtent:
                                                              maxExtent,
                                                          mainAxisExtent:
                                                              _productCardSize *
                                                              1.35,
                                                          crossAxisSpacing: 12,
                                                          mainAxisSpacing: 12,
                                                        ),
                                                    itemCount: products.length,
                                                    itemBuilder: (context, index) {
                                                      final product =
                                                          products[index];
                                                      return Center(
                                                        child: SizedBox(
                                                          width:
                                                              _productCardSize,
                                                          height:
                                                              _productCardSize *
                                                              1.3,
                                                          child:
                                                              _buildProductCard(
                                                                product,
                                                              ),
                                                        ),
                                                      );
                                                    },
                                                  );
                                                },
                                              ),
                                            ),
                                      Positioned(
                                        bottom: 0,
                                        left: 0,
                                        right: 0,
                                        child: _buildTicketsFooter(),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                        if (isNarrow)
                          const Divider(height: 1, thickness: 1)
                        else
                          const VerticalDivider(width: 1, thickness: 1),
                        if (isNarrow)
                          Expanded(
                            flex: 3,
                            child: Align(
                              alignment: Alignment.topCenter,
                              child: ConstrainedBox(
                                constraints: ticketPanelConstraints,
                                child: Container(
                                  margin: EdgeInsets.all(panelMargin),
                                  decoration: BoxDecoration(
                                    color: scheme.surface,
                                    borderRadius: BorderRadius.circular(16),
                                    boxShadow: [
                                      BoxShadow(
                                        color: Colors.black.withOpacity(0.25),
                                        blurRadius: 14,
                                        offset: const Offset(0, 6),
                                        spreadRadius: 0,
                                      ),
                                      BoxShadow(
                                        color: scheme.primary.withOpacity(0.12),
                                        blurRadius: 10,
                                        offset: const Offset(-2, -2),
                                        spreadRadius: -1,
                                      ),
                                    ],
                                  ),
                                  clipBehavior: Clip.antiAlias,
                                  child: _buildTicketPanel(),
                                ),
                              ),
                            ),
                          )
                        else
                          ConstrainedBox(
                            constraints: ticketPanelConstraints,
                            child: Container(
                              margin: EdgeInsets.all(panelMargin),
                              decoration: BoxDecoration(
                                color: scheme.surface,
                                borderRadius: BorderRadius.circular(16),
                                boxShadow: [
                                  BoxShadow(
                                    color: Colors.black.withOpacity(0.25),
                                    blurRadius: 14,
                                    offset: const Offset(0, 6),
                                    spreadRadius: 0,
                                  ),
                                  BoxShadow(
                                    color: scheme.primary.withOpacity(0.12),
                                    blurRadius: 10,
                                    offset: const Offset(-2, -2),
                                    spreadRadius: -1,
                                  ),
                                ],
                              ),
                              clipBehavior: Clip.antiAlias,
                              child: _buildTicketPanel(),
                            ),
                          ),
                      ],
                    );
                  },
                ),
                if (_currentSessionId == null) _buildCashClosedOverlay(),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _onCashPressed() async {
    if (!_canAccessCash) return;

    final sessionId = await cash_repo.CashRepository.getCurrentSessionId();
    if (!mounted) return;

    if (sessionId != null) {
      await CashPanelSheet.show(context, sessionId: sessionId);
      await _refreshCashSession();
      return;
    }

    final opened = await CashOpenDialog.show(context);
    if (!mounted) return;

    if (opened == true) {
      final newSessionId = await cash_repo.CashRepository.getCurrentSessionId();
      if (!mounted) return;

      if (newSessionId != null) {
        await CashPanelSheet.show(context, sessionId: newSessionId);
      }
      await _refreshCashSession();
    }
  }

  Widget _buildCashButton() {
    final isOpen = _currentSessionId != null;
    final theme = Theme.of(context);
    final statusColor = isOpen ? Colors.green : Colors.red;

    return SizedBox(
      height: 42,
      child: ElevatedButton.icon(
        onPressed: _canAccessCash ? _onCashPressed : null,
        style: ElevatedButton.styleFrom(
          backgroundColor: theme.colorScheme.secondary,
          foregroundColor: theme.colorScheme.onSecondary,
          disabledBackgroundColor: Colors.grey.shade300,
          disabledForegroundColor: Colors.grey.shade600,
          elevation: 2,
          padding: const EdgeInsets.symmetric(horizontal: 16),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
        ),
        icon: const Icon(Icons.point_of_sale, size: 20),
        label: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
              'Caja',
              style: TextStyle(fontWeight: FontWeight.bold, fontSize: 14),
            ),
            const SizedBox(width: 10),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(999),
                border: Border.all(
                  color: statusColor.withOpacity(0.95),
                  width: 1.2,
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    isOpen ? Icons.lock_open : Icons.lock,
                    size: 14,
                    color: statusColor,
                  ),
                  const SizedBox(width: 6),
                  Text(
                    isOpen ? 'Abierta' : 'Cerrada',
                    style: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w900,
                      color: Colors.black,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCashClosedOverlay() {
    return Positioned.fill(
      child: Container(
        color: Colors.black.withOpacity(0.7),
        child: Center(
          child: Container(
            width: 400,
            padding: const EdgeInsets.all(32),
            decoration: BoxDecoration(
              color: const Color(0xFF1E1E1E),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(
                color: const Color(0xFFD4AF37).withOpacity(0.3),
              ),
              boxShadow: [
                BoxShadow(color: Colors.black.withOpacity(0.5), blurRadius: 20),
              ],
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: const Color(0xFFD4AF37).withOpacity(0.2),
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(
                    Icons.point_of_sale,
                    size: 48,
                    color: Color(0xFFD4AF37),
                  ),
                ),
                const SizedBox(height: 24),
                const Text(
                  'CAJA CERRADA',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 12),
                Text(
                  'Debe abrir la caja para iniciar el turno\ny poder realizar ventas.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.grey.shade400, fontSize: 14),
                ),
                const SizedBox(height: 28),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    onPressed: () async {
                      final result = await CashOpenDialog.show(context);
                      if (result == true) await _refreshCashSession();
                    },
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFFD4AF37),
                      foregroundColor: Colors.black,
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                    icon: const Icon(Icons.lock_open, size: 20),
                    label: const Text(
                      'ABRIR CAJA',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildProductCard(ProductModel product) {
    final qtyInCart = _currentCart.getQuantityForProduct(product.id ?? -1);
    final effectiveStock = product.stock - qtyInCart;
    final isLowStock = effectiveStock > 0 && effectiveStock <= 10;
    final isOutOfStock = effectiveStock <= 0;
    final stockColor = isOutOfStock
        ? Colors.red.shade600
        : (isLowStock ? Colors.orange.shade600 : scheme.primary.withOpacity(0.85));

    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(12),
        color: Colors.white,
        boxShadow: const [
          BoxShadow(
            color: Color(0x1A0F172A),
            blurRadius: 12,
            spreadRadius: 1,
            offset: Offset(0, 4),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(12),
        child: Material(
          color: Colors.transparent,
          child: InkWell(
            onTap: isOutOfStock ? null : () => _addProductToCart(product),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Imagen del producto más compacta
                Expanded(
                  flex: 3,
                  child: Stack(
                    fit: StackFit.expand,
                    children: [
                      ProductThumbnail.fromProduct(
                        product,
                        width: double.infinity,
                        height: double.infinity,
                        borderRadius: BorderRadius.circular(12),
                        showBorder: false,
                      ),
                      // Badge de código en esquina superior derecha
                      Positioned(
                        top: 6,
                        right: 6,
                        child: Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 6,
                            vertical: 3,
                          ),
                          decoration: BoxDecoration(
                            color: Colors.black.withOpacity(0.75),
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Text(
                            product.code.toUpperCase(),
                            style: const TextStyle(
                              fontSize: 7,
                              fontWeight: FontWeight.w700,
                              color: Colors.white,
                              letterSpacing: 0.3,
                            ),
                          ),
                        ),
                      ),
                      // Badge de cantidad en carrito
                      if (qtyInCart > 0)
                        Positioned(
                          top: 6,
                          left: 6,
                          child: Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 6,
                              vertical: 3,
                            ),
                            decoration: BoxDecoration(
                              color: const Color(0xFFD4AF37),
                              borderRadius: BorderRadius.circular(6),
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.black.withOpacity(0.2),
                                  blurRadius: 4,
                                ),
                              ],
                            ),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                const Icon(
                                  Icons.shopping_cart,
                                  size: 10,
                                  color: Colors.white,
                                ),
                                const SizedBox(width: 3),
                                Text(
                                  qtyInCart.toInt().toString(),
                                  style: const TextStyle(
                                    fontSize: 8,
                                    fontWeight: FontWeight.w900,
                                    color: Colors.white,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
                // Información del producto
                Expanded(
                  flex: 2,
                  child: Container(
                    padding: const EdgeInsets.all(8),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        // Nombre del producto
                        Text(
                          product.name,
                          style: TextStyle(
                            fontSize: 9,
                            fontWeight: FontWeight.w700,
                            height: 1.2,
                            color: Colors.grey.shade800,
                          ),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 4),
                        // Precio y Stock en fila
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          crossAxisAlignment: CrossAxisAlignment.center,
                          children: [
                            // Precio
                            Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Text(
                                  'PRECIO',
                                  style: TextStyle(
                                    fontSize: 6,
                                    fontWeight: FontWeight.w600,
                                    color: Colors.grey.shade500,
                                    letterSpacing: 0.3,
                                  ),
                                ),
                                Text(
                                  '\$${product.salePrice.toStringAsFixed(2)}',
                                  style: const TextStyle(
                                    fontSize: 11,
                                    fontWeight: FontWeight.w900,
                                    color: Color(0xFF065F46),
                                  ),
                                ),
                              ],
                            ),
                            // Stock badge
                            Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 6,
                                vertical: 4,
                              ),
                              decoration: BoxDecoration(
                                color: stockColor,
                                borderRadius: BorderRadius.circular(6),
                              ),
                              child: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(
                                    isOutOfStock
                                        ? Icons.remove_circle_outline
                                        : Icons.inventory_2,
                                    size: 10,
                                    color: Colors.white,
                                  ),
                                  const SizedBox(width: 3),
                                  Text(
                                    isOutOfStock
                                        ? 'Agotado'
                                        : '${effectiveStock.toInt()}',
                                    style: const TextStyle(
                                      fontSize: 8,
                                      fontWeight: FontWeight.w800,
                                      color: Colors.white,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildCategoryDropdown() {
    final allOption = 'Todas';
    final items = [allOption, ..._categories.map((c) => c.name)];
    return Padding(
      padding: const EdgeInsets.only(right: 4),
      child: PopupMenuButton<String>(
        tooltip: 'Elegir categoría',
        offset: const Offset(0, 42),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        initialValue: _selectedCategory ?? allOption,
        onSelected: (value) =>
            _onCategorySelected(value == allOption ? null : value),
        itemBuilder: (context) => items
            .map(
              (name) => PopupMenuItem<String>(
                value: name,
                child: Row(
                  children: [
                    Icon(
                      name == allOption
                          ? Icons.filter_alt_off_outlined
                          : Icons.category_outlined,
                      size: 18,
                      color: (_selectedCategory ?? allOption) == name
                          ? scheme.primary
                          : Colors.grey[700],
                    ),
                    const SizedBox(width: 8),
                    Text(
                      name,
                      style: TextStyle(
                        fontWeight: (_selectedCategory ?? allOption) == name
                            ? FontWeight.w700
                            : FontWeight.w500,
                      ),
                    ),
                  ],
                ),
              ),
            )
            .toList(),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 9),
          decoration: BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: scheme.primary.withOpacity(0.3), width: 1),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.filter_list, size: 18, color: scheme.primary),
              const SizedBox(width: 6),
              Text(
                _selectedCategory ?? 'Categoría',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                  color: scheme.primary,
                ),
              ),
              const SizedBox(width: 4),
              Icon(
                Icons.keyboard_arrow_down_rounded,
                size: 18,
                color: scheme.primary,
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _build3DControlBar() {
    final bg = Theme.of(context).scaffoldBackgroundColor;
    return Container(
      padding: const EdgeInsets.all(6),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [bg.withOpacity(0.9), bg.withOpacity(0.7)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(16),
        boxShadow: const [
          BoxShadow(
            color: Colors.black26,
            blurRadius: 12,
            offset: Offset(0, 6),
          ),
          BoxShadow(
            color: Colors.white24,
            blurRadius: 10,
            offset: Offset(-2, -2),
            spreadRadius: -2,
          ),
        ],
      ),
      child: Row(
        children: [
          Expanded(
            child: Container(
              height: 50,
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(12),
                boxShadow: const [
                  BoxShadow(
                    color: Colors.black12,
                    blurRadius: 8,
                    offset: Offset(0, 2),
                  ),
                ],
              ),
              child: Row(
                children: [
                  const SizedBox(width: 12),
                  const Icon(Icons.search, color: Colors.grey, size: 20),
                  Expanded(
                    child: TextField(
                      controller: _searchController,
                      focusNode: _searchFocusNode,
                      decoration: const InputDecoration(
                        hintText: 'Buscar por nombre, código...',
                        border: InputBorder.none,
                        contentPadding: EdgeInsets.symmetric(
                          horizontal: 12,
                          vertical: 14,
                        ),
                      ),
                      onChanged: _searchProducts,
                    ),
                  ),
                  _buildCategoryDropdown(),
                  IconButton(
                    icon: Icon(
                      Icons.filter_list,
                      color: _productFilter.hasActiveFilters
                          ? Colors.orange
                          : scheme.primary,
                    ),
                    onPressed: _openFilterDialog,
                    tooltip: 'Filtros avanzados',
                  ),
                  Container(height: 28, width: 1, color: Colors.grey.shade300),
                  IconButton(
                    icon: Icon(Icons.barcode_reader, color: scheme.primary),
                    onPressed: () {
                      showDialog(
                        context: context,
                        builder: (context) => BarcodeInfoDialog(
                          config: _scannerConfig,
                          terminalId: _scannerTerminalId,
                        ),
                      );
                    },
                    tooltip: 'Escanear código de barras',
                  ),
                  const SizedBox(width: 4),
                ],
              ),
            ),
          ),
          const SizedBox(width: 12),
          _buildCashButton(),
        ],
      ),
    );
  }

  Widget _buildOperationButton({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onPressed,
  }) {
    return ElevatedButton(
      onPressed: onPressed,
      style: ElevatedButton.styleFrom(
        backgroundColor: color,
        foregroundColor: Colors.white,
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 16),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
        ),
        elevation: 10,
        shadowColor: Colors.black54,
        minimumSize: const Size.fromHeight(44),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, size: 20),
          const SizedBox(width: 8),
          Flexible(
            child: Text(
              label,
              style: const TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w800,
                letterSpacing: 0.4,
              ),
              textAlign: TextAlign.center,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTicketsFooter() {
    return Container(
      height: 64,
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          colors: [Color(0xFF0F2F48), Color(0xFF163B5A)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        boxShadow: const [
          BoxShadow(
            color: Colors.black54,
            blurRadius: 14,
            offset: Offset(0, -4),
          ),
        ],
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
        child: Row(
          children: [
            Expanded(
              child: _buildOperationButton(
                icon: Icons.account_balance,
                label: 'Créditos',
                color: const Color(0xFF0E7A6F),
                onPressed: () => context.go('/credits-list'),
              ),
            ),
            if (_isAdmin || _permissions.canProcessReturns) ...[
              const SizedBox(width: 10),
              Expanded(
                child: _buildOperationButton(
                  icon: Icons.assignment_return,
                  label: 'Cotizaciones',
                  color: const Color(0xFF0D5C9D),
                  onPressed: () => context.go('/quotes-list'),
                ),
              ),
            ],
            const SizedBox(width: 10),
            Expanded(
              child: _buildOperationButton(
                icon: Icons.assignment_return,
                label: 'Devoluciones',
                color: const Color(0xFFCC8A00),
                onPressed: () => context.go('/returns-list'),
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// Panel de ticket refactorizado con 3 cards profesionales
  Widget _buildTicketPanel() {
    return Column(
      children: [
        // CARD A: Ticket / Cliente
        _buildTicketHeaderCard(),
        const SizedBox(height: 12),

        // CARD B: Detalle de la venta (scrollable)
        Expanded(child: _buildItemsListCard()),
        const SizedBox(height: 12),

        // CARD C: Resumen + Total + Acciones (sticky)
        _buildTotalAndActionsCard(),
      ],
    );
  }

  /// CARD A: Ticket / Cliente
  Widget _buildTicketHeaderCard() {
    final totalTickets = _carts.length;

    return Card(
      margin: const EdgeInsets.fromLTRB(12, 12, 12, 0),
      elevation: 2,
      shadowColor: Colors.black12,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: Colors.grey.shade200, width: 1),
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [scheme.primary.withOpacity(0.92), Colors.blue.shade600],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                borderRadius: BorderRadius.circular(10),
                boxShadow: [
                  BoxShadow(
                    color: scheme.primary.withOpacity(0.18),
                    blurRadius: 8,
                    offset: const Offset(0, 2),
                  ),
                ],
              ),
              child: Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: Colors.white.withOpacity(0.16),
                      border: Border.all(color: Colors.white.withOpacity(0.35)),
                    ),
                    child: const Icon(
                      Icons.description_outlined,
                      size: 18,
                      color: Colors.white,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: InkWell(
                      onTap: _showTicketSelector,
                      child: Row(
                        children: [
                          Flexible(
                            child: Text(
                              totalTickets == 1
                                  ? '1 Ticket'
                                  : '${_currentCart.displayName} (${totalTickets} en cola)',
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 15,
                                fontWeight: FontWeight.w700,
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          const SizedBox(width: 6),
                          const Icon(
                            Icons.arrow_drop_down,
                            color: Colors.white,
                          ),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Container(
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: Colors.white.withOpacity(0.18),
                      border: Border.all(color: Colors.white.withOpacity(0.35)),
                    ),
                    child: IconButton(
                      icon: const Icon(
                        Icons.add,
                        color: Colors.white,
                        size: 20,
                      ),
                      padding: const EdgeInsets.all(8),
                      constraints: const BoxConstraints(),
                      tooltip: 'Nuevo ticket',
                      onPressed: _addNewTicket,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _showClientPicker,
                    icon: const Icon(Icons.group, size: 18),
                    label: const Text('Clientes'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.white,
                      foregroundColor: scheme.primary.withOpacity(0.98),
                      elevation: 0,
                      padding: const EdgeInsets.symmetric(vertical: 10),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                        side: BorderSide(color: scheme.primary.withOpacity(0.14)),
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _showQuickItemDialog,
                    icon: const Icon(Icons.flash_on, size: 18),
                    label: const Text('Venta Rápida'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.indigo.shade50,
                      foregroundColor: Colors.indigo.shade700,
                      elevation: 0,
                      padding: const EdgeInsets.symmetric(vertical: 10),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10),
                        side: BorderSide(color: Colors.indigo.shade100),
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  /// CARD B: Detalle de la venta (lista scrollable)
  Widget _buildItemsListCard() {
    final itemCount = _currentCart.items.length;

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12),
      elevation: 2,
      shadowColor: Colors.black12,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: Colors.grey.shade200, width: 1),
      ),
      child: LayoutBuilder(
        builder: (context, constraints) {
          // Durante el arranque/redimensionado la altura puede llegar a 0–20px,
          // y el header (≈47px) causa overflow. En ese caso, no renderizar.
          if (constraints.maxHeight > 0 && constraints.maxHeight < 80) {
            return const SizedBox.shrink();
          }

          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header del card
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: Colors.grey.shade50,
                  borderRadius: const BorderRadius.only(
                    topLeft: Radius.circular(12),
                    topRight: Radius.circular(12),
                  ),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    const Text(
                      'Detalle de la venta',
                      style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    if (itemCount > 0)
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 10,
                          vertical: 4,
                        ),
                        decoration: BoxDecoration(
                          color: scheme.primary.withOpacity(0.14),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Text(
                          '$itemCount ${itemCount == 1 ? "artículo" : "artículos"}',
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                            color: scheme.primary.withOpacity(0.98),
                          ),
                        ),
                      ),
                  ],
                ),
              ),

              // Lista de items
              Expanded(
                child: _currentCart.items.isEmpty
                    ? _buildEmptyCartView()
                    : ListView.separated(
                        padding: const EdgeInsets.all(8),
                        itemCount: itemCount,
                        separatorBuilder: (context, index) =>
                            const Divider(height: 1),
                        itemBuilder: (context, index) {
                          final item = _currentCart.items[index];
                          return _buildCartItemRow(item, index);
                        },
                      ),
              ),
            ],
          );
        },
      ),
    );
  }

  Widget _buildEmptyCartView() {
    return LayoutBuilder(
      builder: (context, constraints) {
        final compact =
            constraints.maxHeight > 0 && constraints.maxHeight < 120;
        final iconSize = compact ? 34.0 : 48.0;
        final titleSize = compact ? 13.0 : 15.0;
        final subtitleSize = compact ? 11.0 : 12.0;
        final gap1 = compact ? 8.0 : 12.0;
        final gap2 = compact ? 4.0 : 6.0;

        return Center(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.receipt_long_outlined,
                  size: iconSize,
                  color: Colors.grey.shade300,
                ),
                SizedBox(height: gap1),
                Text(
                  'Ticket vacío',
                  style: TextStyle(
                    color: Colors.grey.shade600,
                    fontSize: titleSize,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                SizedBox(height: gap2),
                Text(
                  'Agrega productos desde el catálogo',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    color: Colors.grey.shade400,
                    fontSize: subtitleSize,
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildCartItemRow(SaleItemModel item, int index) {
    final isSelected = _selectedCartItemIndex == index;
    final subtotal = (item.qty * item.unitPrice) - item.discountLine;

    return InkWell(
      onTap: () => setState(() => _selectedCartItemIndex = index),
      onDoubleTap: () => _showEditItemDialog(item, index),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
        decoration: BoxDecoration(
          color: isSelected ? scheme.primary.withOpacity(0.08) : Colors.transparent,
          borderRadius: BorderRadius.circular(8),
          border: isSelected
              ? Border.all(color: scheme.primary.withOpacity(0.32), width: 1.5)
              : null,
        ),
        child: Row(
          children: [
            // Cantidad badge
            Container(
              width: 32,
              height: 32,
              decoration: BoxDecoration(
                color: scheme.primary.withOpacity(0.14),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Center(
                child: Text(
                  '${item.qty.toInt()}',
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.bold,
                    color: scheme.primary.withOpacity(0.98),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 10),

            // Nombre y código del producto
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    item.productNameSnapshot,
                    style: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2),
                  Text(
                    'Precio: RD\$${item.unitPrice.toStringAsFixed(2)}',
                    style: TextStyle(fontSize: 10, color: Colors.grey.shade600),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),

            // Controles de cantidad
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                _buildCompactStepperButton(Icons.remove, () {
                  if (item.qty > 1) {
                    setState(
                      () => _currentCart.updateQuantity(index, item.qty - 1),
                    );
                  }
                }),
                const SizedBox(width: 4),
                _buildCompactStepperButton(
                  Icons.add,
                  () => _incrementCartItemQty(item, index),
                ),
              ],
            ),
            const SizedBox(width: 10),

            // Subtotal
            Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                if (item.discountLine > 0)
                  Text(
                    '-\$${item.discountLine.toStringAsFixed(0)}',
                    style: TextStyle(
                      fontSize: 9,
                      color: Colors.red.shade600,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                Text(
                  '\$${subtotal.toStringAsFixed(2)}',
                  style: TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.bold,
                    color: scheme.primary.withOpacity(0.92),
                  ),
                ),
              ],
            ),
            const SizedBox(width: 8),

            // Botón eliminar
            InkWell(
              onTap: () => setState(() => _currentCart.removeItem(index)),
              borderRadius: BorderRadius.circular(4),
              child: Container(
                padding: const EdgeInsets.all(4),
                child: Icon(
                  Icons.delete_outline,
                  size: 18,
                  color: Colors.red.shade300,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCompactStepperButton(IconData icon, VoidCallback onTap) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(4),
      child: Container(
        width: 24,
        height: 24,
        decoration: BoxDecoration(
          color: Colors.grey.shade100,
          borderRadius: BorderRadius.circular(4),
          border: Border.all(color: Colors.grey.shade300, width: 0.5),
        ),
        child: Icon(icon, size: 14, color: Colors.grey.shade700),
      ),
    );
  }

  /// CARD C: Resumen + Total + Acciones (sticky al fondo)
  Widget _buildTotalAndActionsCard() {
    final content = Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        // Switches y opciones fiscales
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 12, 6),
          child: Column(
            children: [
              Row(
                children: [
                  Expanded(
                    child: SwitchListTile(
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      title: Text(
                        'ITBIS ${(_currentCart.itbisRate * 100).toInt()}%',
                        style: const TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      value: _currentCart.itbisEnabled,
                      onChanged: _currentCart.fiscalEnabled
                          ? null
                          : (value) => setState(
                              () => _currentCart.itbisEnabled = value,
                            ),
                      activeColor: scheme.primary,
                    ),
                  ),
                  Expanded(
                    child: SwitchListTile(
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      title: const Text(
                        'Comprobante',
                        style: TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      value: _currentCart.fiscalEnabled,
                      onChanged: (value) async {
                        if (!value) {
                          setState(() {
                            _currentCart.fiscalEnabled = false;
                            _currentCart.selectedNcf = null;
                          });
                          return;
                        }

                        setState(() {
                          _currentCart.fiscalEnabled = true;
                          _currentCart.itbisEnabled = true;
                        });

                        await _loadAvailableNcfs();
                        if (!mounted) return;

                        if (_availableNcfs.isEmpty) {
                          setState(() {
                            _currentCart.fiscalEnabled = false;
                            _currentCart.selectedNcf = null;
                          });
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text(
                                'No hay NCF disponibles. Hable con Administración para agregarlo.',
                              ),
                              backgroundColor: Colors.red,
                            ),
                          );
                          return;
                        }

                        setState(
                          () =>
                              _currentCart.selectedNcf ??= _availableNcfs.first,
                        );
                      },
                      activeColor: const Color(0xFFD4AF37),
                    ),
                  ),
                ],
              ),

              if (_currentCart.fiscalEnabled) ...[
                const SizedBox(height: 6),
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        _currentCart.selectedNcf == null
                            ? 'NCF: (no seleccionado)'
                            : 'NCF: ${_currentCart.selectedNcf!.type} - ${_currentCart.selectedNcf!.buildNcf()}',
                        style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                          color: _currentCart.selectedNcf == null
                              ? Colors.red.shade700
                              : Colors.grey.shade800,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    TextButton(
                      onPressed: _availableNcfs.isEmpty
                          ? null
                          : () async {
                              final selected = await showDialog<NcfBookModel>(
                                context: context,
                                builder: (_) => SimpleDialog(
                                  title: const Text('Seleccionar NCF'),
                                  children: _availableNcfs
                                      .map(
                                        (ncf) => SimpleDialogOption(
                                          onPressed: () =>
                                              Navigator.of(context).pop(ncf),
                                          child: Text(
                                            '${ncf.type} - ${ncf.buildNcf()} (${ncf.toN - ncf.nextN + 1})',
                                            style: const TextStyle(
                                              fontSize: 12,
                                            ),
                                          ),
                                        ),
                                      )
                                      .toList(growable: false),
                                ),
                              );
                              if (selected != null && mounted) {
                                setState(
                                  () => _currentCart.selectedNcf = selected,
                                );
                              }
                            },
                      child: const Text(
                        'Cambiar',
                        style: TextStyle(fontSize: 12),
                      ),
                    ),
                  ],
                ),
              ],
            ],
          ),
        ),
        const Divider(height: 1),

        // Resumen de totales
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
              colors: [Colors.grey.shade50, Colors.white],
            ),
          ),
          child: Column(
            children: [
              _buildSummaryRow(
                'Subtotal:',
                _currentCart.calculateGrossSubtotal(),
                false,
              ),
              if (_currentCart.calculateTotalDiscountsCombined() > 0) ...[
                const SizedBox(height: 4),
                _buildSummaryRow(
                  'Descuentos:',
                  _currentCart.calculateTotalDiscountsCombined(),
                  false,
                  color: Colors.red.shade700,
                ),
              ],
              if (_currentCart.itbisEnabled) ...[
                const SizedBox(height: 4),
                _buildSummaryRow(
                  'ITBIS ${(_currentCart.itbisRate * 100).toInt()}%:',
                  _currentCart.calculateItbis(),
                  false,
                ),
              ],
              if (_currentCart.itbisEnabled ||
                  _currentCart.calculateTotalDiscountsCombined() > 0) ...[
                Padding(
                  padding: EdgeInsets.symmetric(vertical: 8),
                  child: Divider(thickness: 1.5, color: scheme.primary),
                ),
              ],

              // Total destacado
              GestureDetector(
                onDoubleTap: _showTotalDiscountDialog,
                child: Tooltip(
                  message: 'Doble click para descuento',
                  child: Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: scheme.primary.withOpacity(0.08),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(
                        color: scheme.primary.withOpacity(0.22),
                        width: 2.2,
                      ),
                    ),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Row(
                          children: [
                            Icon(
                              Icons.attach_money,
                              size: 20,
                              color: scheme.primary.withOpacity(0.92),
                            ),
                            const SizedBox(width: 6),
                            Text(
                              'TOTAL:',
                              style: TextStyle(
                                fontSize: 19,
                                fontWeight: FontWeight.w800,
                                color: scheme.primary,
                              ),
                            ),
                          ],
                        ),
                        Text(
                          'RD\$${_currentCart.calculateTotal().toStringAsFixed(2)}',
                          style: TextStyle(
                            fontSize: 26,
                            fontWeight: FontWeight.w900,
                            color: scheme.primary.withOpacity(0.98),
                            letterSpacing: 0.5,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),

        // Botones de acción
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
          child: Column(
            children: [
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: _currentCart.items.isEmpty
                      ? null
                      : () => _processPayment(SaleKind.invoice),
                  icon: const Icon(Icons.payment, size: 22),
                  label: const Text(
                    'COBRAR (F8)',
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w900,
                      letterSpacing: 0.6,
                    ),
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: scheme.primary,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(14),
                    ),
                    elevation: 10,
                    shadowColor: scheme.primary.withOpacity(0.6),
                  ),
                ),
              ),
              const SizedBox(height: 6),
              SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  onPressed: _currentCart.items.isEmpty ? null : _saveAsQuote,
                  icon: const Icon(Icons.description, size: 18),
                  label: const Text(
                    'COTIZAR',
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 0.5,
                    ),
                  ),
                  style: OutlinedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 13),
                    side: BorderSide(color: Colors.orange.shade200, width: 1.5),
                    foregroundColor: Colors.orange.shade700,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                    backgroundColor: Colors.orange.shade50,
                  ),
                ),
              ),
            ],
          ),
        ),
      ],
    );

    return Card(
      margin: const EdgeInsets.fromLTRB(12, 0, 12, 12),
      elevation: 12,
      shadowColor: Colors.black.withOpacity(0.25),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(color: scheme.primary.withOpacity(0.08), width: 1),
      ),
      child: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            colors: [Colors.white, Colors.grey.shade50, Colors.white],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.circular(16),
          boxShadow: const [
            BoxShadow(
              color: Color(0x14000000),
              blurRadius: 18,
              offset: Offset(0, 10),
              spreadRadius: 1,
            ),
          ],
        ),
        child: ConstrainedBox(
          constraints: const BoxConstraints(minWidth: 320, maxWidth: 460),
          child: content,
        ),
      ),
    );
  }

  Widget _buildSummaryRow(
    String label,
    double amount,
    bool isTotal, {
    Color? color,
  }) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          label,
          style: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: color ?? Colors.grey.shade700,
          ),
        ),
        Text(
          'RD\$${amount.toStringAsFixed(2)}',
          style: TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.bold,
            color: color ?? Colors.black87,
          ),
        ),
      ],
    );
  }

  // Método legacy mantenido para compatibilidad (ya no se usa)
  // ignore: unused_element
  Widget _buildSalesSummary() {
    return Container(
      color: Colors.transparent,
      child: Column(
        children: [
          Container(
            color: Colors.white,
            padding: const EdgeInsets.all(12),
            child: Column(
              children: [
                _buildPendingTicketsBar(),
                const SizedBox(height: 12),
                _buildClientSelector(),
                const SizedBox(height: 8),
                SizedBox(
                  width: double.infinity,
                  child: OutlinedButton.icon(
                    onPressed: _showQuickItemDialog,
                    icon: const Icon(Icons.add_shopping_cart, size: 18),
                    label: const Text(
                      'Venta Rápida',
                      style: TextStyle(fontSize: 13),
                    ),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: scheme.primary,
                      side: BorderSide(color: scheme.primary),
                      padding: const EdgeInsets.symmetric(vertical: 10),
                    ),
                  ),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: _currentCart.items.isEmpty
                ? LayoutBuilder(
                    builder: (context, constraints) {
                      const contentHeight = 64 + 8 + 23 + 8 + 19;
                      final topPadding =
                          ((constraints.maxHeight - contentHeight) / 2).clamp(
                            16.0,
                            120.0,
                          );

                      return ListView(
                        padding: EdgeInsets.fromLTRB(12, topPadding, 12, 16),
                        children: [
                          Center(
                            child: Icon(
                              Icons.receipt_long_outlined,
                              size: 64,
                              color: Colors.grey.shade300,
                            ),
                          ),
                          const SizedBox(height: 8),
                          Center(
                            child: Text(
                              'Ticket vacío',
                              style: TextStyle(
                                color: Colors.grey.shade600,
                                fontSize: 16,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                          ),
                          const SizedBox(height: 8),
                          Center(
                            child: Text(
                              'Agrega productos desde el catálogo',
                              textAlign: TextAlign.center,
                              style: TextStyle(
                                color: Colors.grey.shade400,
                                fontSize: 13,
                              ),
                            ),
                          ),
                        ],
                      );
                    },
                  )
                : ListView.builder(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    itemCount: _currentCart.items.length,
                    itemBuilder: (context, index) {
                      final item = _currentCart.items[index];
                      return _buildCartItemCard(item, index);
                    },
                  ),
          ),
          Container(
            decoration: BoxDecoration(
              color: Colors.white,
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.08),
                  blurRadius: 12,
                  offset: const Offset(0, -3),
                ),
              ],
            ),
            child: Column(
              children: [
                Container(
                  color: Colors.white,
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    children: [
                      SwitchListTile(
                        dense: true,
                        contentPadding: EdgeInsets.zero,
                        title: Text(
                          'ITBIS ${(_currentCart.itbisRate * 100).toInt()}%',
                          style: const TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        value: _currentCart.itbisEnabled,
                        onChanged: _currentCart.fiscalEnabled
                            ? null
                            : (value) => setState(
                                () => _currentCart.itbisEnabled = value,
                              ),
                        activeColor: scheme.primary,
                      ),
                      const Divider(height: 8),
                      SwitchListTile(
                        dense: true,
                        contentPadding: EdgeInsets.zero,
                        title: const Text(
                          'Valor Fiscal',
                          style: TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        subtitle: _currentCart.fiscalEnabled
                            ? const Text(
                                'NCF requerido',
                                style: TextStyle(fontSize: 11),
                              )
                            : null,
                        value: _currentCart.fiscalEnabled,
                        onChanged: (value) async {
                          if (!value) {
                            setState(() {
                              _currentCart.fiscalEnabled = false;
                              _currentCart.selectedNcf = null;
                            });
                            return;
                          }

                          // Activar valor fiscal implica ITBIS activo
                          setState(() {
                            _currentCart.fiscalEnabled = true;
                            _currentCart.itbisEnabled = true;
                          });

                          await _loadAvailableNcfs();
                          if (!mounted) return;

                          if (_availableNcfs.isEmpty) {
                            setState(() {
                              _currentCart.fiscalEnabled = false;
                              _currentCart.selectedNcf = null;
                            });
                            ScaffoldMessenger.of(context).showSnackBar(
                              const SnackBar(
                                content: Text(
                                  'No hay NCF disponibles. Hable con Administración para agregarlo.',
                                ),
                                backgroundColor: Colors.red,
                              ),
                            );
                            return;
                          }

                          // Preseleccionar el primero disponible para que quede listo
                          setState(() {
                            _currentCart.selectedNcf ??= _availableNcfs.first;
                          });
                        },
                        activeColor: const Color(0xFFD4AF37),
                      ),
                      if (_currentCart.fiscalEnabled) ...[
                        const SizedBox(height: 8),
                        Container(
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: const Color(0xFFD4AF37).withOpacity(0.1),
                            border: Border.all(color: const Color(0xFFD4AF37)),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Text(
                                'Comprobante Fiscal (NCF)',
                                style: TextStyle(
                                  fontSize: 12,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                              const SizedBox(height: 8),
                              if (_availableNcfs.isEmpty)
                                Text(
                                  'No hay NCF disponibles. Hable con Administración para agregarlo.',
                                  style: TextStyle(
                                    fontSize: 11,
                                    color: Colors.red.shade700,
                                  ),
                                )
                              else
                                DropdownButtonFormField<NcfBookModel>(
                                  value: _currentCart.selectedNcf,
                                  decoration: const InputDecoration(
                                    isDense: true,
                                    contentPadding: EdgeInsets.symmetric(
                                      horizontal: 10,
                                      vertical: 8,
                                    ),
                                    border: OutlineInputBorder(),
                                  ),
                                  items: _availableNcfs.map((ncf) {
                                    return DropdownMenuItem(
                                      value: ncf,
                                      child: Text(
                                        '${ncf.type} - ${ncf.buildNcf()} (${ncf.toN - ncf.nextN + 1} disponibles)',
                                        style: const TextStyle(fontSize: 11),
                                      ),
                                    );
                                  }).toList(),
                                  onChanged: (ncf) => setState(
                                    () => _currentCart.selectedNcf = ncf,
                                  ),
                                ),
                            ],
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
                const Divider(height: 1),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      begin: Alignment.topCenter,
                      end: Alignment.bottomCenter,
                      colors: [Colors.grey.shade50, Colors.white],
                    ),
                  ),
                  child: Column(
                    children: [
                      _buildTotalRow(
                        'Subtotal:',
                        _currentCart.calculateGrossSubtotal(),
                        false,
                        isSubtotal: true,
                      ),
                      const SizedBox(height: 6),
                      if (_currentCart.calculateTotalDiscountsCombined() >
                          0) ...[
                        _buildTotalRow(
                          'Descuentos:',
                          _currentCart.calculateTotalDiscountsCombined(),
                          false,
                          color: Colors.red.shade700,
                        ),
                        const SizedBox(height: 6),
                      ],
                      if (_currentCart.itbisEnabled)
                        _buildTotalRow(
                          'ITBIS ${(_currentCart.itbisRate * 100).toInt()}%:',
                          _currentCart.calculateItbis(),
                          false,
                          isTax: true,
                        ),
                      if (_currentCart.itbisEnabled ||
                          _currentCart.calculateTotalDiscountsCombined() >
                              0) ...[
                        Padding(
                          padding: EdgeInsets.symmetric(vertical: 10),
                          child: Divider(thickness: 2, color: scheme.primary),
                        ),
                      ],
                      GestureDetector(
                        onDoubleTap: _showTotalDiscountDialog,
                        child: Tooltip(
                          message: 'Doble click para aplicar descuento',
                          child: _buildTotalRow(
                            'TOTAL:',
                            _currentCart.calculateTotal(),
                            true,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
                  child: Column(
                    children: [
                      SizedBox(
                        width: double.infinity,
                        child: ElevatedButton.icon(
                          onPressed: _currentCart.items.isEmpty
                              ? null
                              : () => _processPayment(SaleKind.invoice),
                          icon: const Icon(Icons.payment, size: 24),
                          label: const Text(
                            'COBRAR',
                            style: TextStyle(
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          style: ElevatedButton.styleFrom(
                            backgroundColor: scheme.primary,
                            padding: const EdgeInsets.symmetric(vertical: 16),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(12),
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 8),
                      SizedBox(
                        width: double.infinity,
                        child: OutlinedButton.icon(
                          onPressed: _currentCart.items.isEmpty
                              ? null
                              : _saveAsQuote,
                          icon: const Icon(Icons.description),
                          label: const Text('COTIZAR'),
                          style: OutlinedButton.styleFrom(
                            padding: const EdgeInsets.symmetric(vertical: 14),
                            side: BorderSide(color: Colors.orange.shade300),
                            foregroundColor: Colors.orange,
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(12),
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCartItemCard(SaleItemModel item, int index) {
    final isSelected = _selectedCartItemIndex == index;
    final subtotal = (item.qty * item.unitPrice) - item.discountLine;

    return TweenAnimationBuilder<double>(
      tween: Tween(begin: 0.0, end: 1.0),
      duration: const Duration(milliseconds: 300),
      curve: Curves.easeOut,
      builder: (context, value, child) => Transform.scale(
        scale: 0.8 + (0.2 * value.clamp(0.0, 1.0)),
        child: Opacity(opacity: value.clamp(0.0, 1.0), child: child),
      ),
      child: Card(
        margin: const EdgeInsets.only(bottom: 3),
        elevation: isSelected ? 4 : 2,
        shadowColor: isSelected ? scheme.primary.withOpacity(0.3) : Colors.black26,
        color: isSelected ? scheme.primary.withOpacity(0.08) : Colors.white,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(6),
          side: isSelected
              ? BorderSide(color: scheme.primary.withOpacity(0.45), width: 1.5)
              : BorderSide(color: Colors.grey.shade200, width: 0.5),
        ),
        child: InkWell(
          onTap: () => setState(() => _selectedCartItemIndex = index),
          onDoubleTap: () => _showEditItemDialog(item, index),
          borderRadius: BorderRadius.circular(6),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
            child: Row(
              children: [
                Container(
                  width: 28,
                  height: 28,
                  decoration: BoxDecoration(
                    color: scheme.primary.withOpacity(0.14),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Center(
                    child: Text(
                      '${item.qty.toInt()}',
                      style: TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                        color: scheme.primary.withOpacity(0.98),
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  flex: 3,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        item.productNameSnapshot.toUpperCase(),
                        style: const TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                          height: 1.1,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      Text(
                        item.productCodeSnapshot.toUpperCase(),
                        style: TextStyle(
                          fontSize: 9,
                          color: Colors.grey.shade600,
                          height: 1.1,
                        ),
                      ),
                    ],
                  ),
                ),
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    _buildMiniButton(Icons.remove, () {
                      if (item.qty > 1) {
                        setState(
                          () =>
                              _currentCart.updateQuantity(index, item.qty - 1),
                        );
                      }
                    }),
                    _buildMiniButton(
                      Icons.add,
                      () => _incrementCartItemQty(item, index),
                    ),
                  ],
                ),
                const SizedBox(width: 6),
                SizedBox(
                  width: 70,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.end,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (item.discountLine > 0)
                        Text(
                          '-${item.discountLine.toStringAsFixed(0)}',
                          style: TextStyle(
                            fontSize: 8,
                            color: Colors.red.shade600,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      Text(
                        subtotal.toStringAsFixed(2),
                        style: TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.bold,
                          color: scheme.primary.withOpacity(0.92),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 4),
                InkWell(
                  onTap: () => setState(() => _currentCart.removeItem(index)),
                  borderRadius: BorderRadius.circular(4),
                  child: Container(
                    padding: const EdgeInsets.all(4),
                    child: Icon(
                      Icons.close,
                      size: 14,
                      color: Colors.red.shade400,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildMiniButton(IconData icon, VoidCallback onTap) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(4),
      child: Container(
        width: 22,
        height: 22,
        margin: const EdgeInsets.symmetric(horizontal: 1),
        decoration: BoxDecoration(
          color: Colors.grey.shade100,
          borderRadius: BorderRadius.circular(4),
          border: Border.all(color: Colors.grey.shade300, width: 0.5),
        ),
        child: Icon(icon, size: 12, color: Colors.grey.shade700),
      ),
    );
  }

  Widget _buildTotalRow(
    String label,
    double amount,
    bool isTotal, {
    Color? color,
    bool isSubtotal = false,
    bool isTax = false,
  }) {
    return Container(
      padding: isTotal
          ? const EdgeInsets.symmetric(horizontal: 12, vertical: 8)
          : null,
      decoration: isTotal
          ? BoxDecoration(
              color: scheme.primary.withOpacity(0.08),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: scheme.primary.withOpacity(0.22), width: 2),
            )
          : null,
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            children: [
              if (isTotal)
                Icon(Icons.attach_money, size: 20, color: scheme.primary.withOpacity(0.92)),
              if (isTotal) const SizedBox(width: 4),
              Text(
                label,
                style: TextStyle(
                  fontSize: isTotal ? 20 : 13,
                  fontWeight: isTotal ? FontWeight.bold : FontWeight.w600,
                  color:
                      color ??
                      (isTotal ? scheme.primary : Colors.grey.shade700),
                  letterSpacing: isTotal ? 0.5 : 0,
                ),
              ),
            ],
          ),
          Text(
            '\$${amount.toStringAsFixed(2)}',
            style: TextStyle(
              fontSize: isTotal ? 24 : 14,
              fontWeight: FontWeight.bold,
              color: color ?? (isTotal ? scheme.primary.withOpacity(0.98) : Colors.black87),
              letterSpacing: isTotal ? 0.5 : 0,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildClientSelector() {
    return Container(
      decoration: BoxDecoration(
        color: Colors.grey.shade100,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.grey.shade300),
      ),
      child: Row(
        children: [
          Expanded(
            child: _currentCart.selectedClient == null
                ? TextButton.icon(
                    onPressed: _showClientPicker,
                    icon: const Icon(Icons.person_add, size: 20),
                    label: const Text('Seleccionar Cliente'),
                    style: TextButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 12),
                    ),
                  )
                : InkWell(
                    onTap: _showClientPicker,
                    child: Padding(
                      padding: EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 10,
                      ),
                      child: Row(
                        children: [
                          Icon(
                            Icons.person,
                            size: 20,
                            color: scheme.primary,
                          ),
                          SizedBox(width: 8),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  _currentCart.selectedClient!.nombre,
                                  style: const TextStyle(
                                    fontSize: 13,
                                    fontWeight: FontWeight.w600,
                                  ),
                                  maxLines: 1,
                                  overflow: TextOverflow.ellipsis,
                                ),
                                if (_currentCart.selectedClient!.telefono !=
                                    null)
                                  Text(
                                    _currentCart.selectedClient!.telefono!,
                                    style: TextStyle(
                                      fontSize: 11,
                                      color: Colors.grey.shade600,
                                    ),
                                  ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
          ),
          if (_currentCart.selectedClient != null)
            IconButton(
              icon: const Icon(Icons.close, size: 18),
              onPressed: _removeClient,
              tooltip: 'Quitar cliente',
            ),
        ],
      ),
    );
  }

  Widget _buildCartTab(int index, _Cart cart) {
    final isActive = index == _currentCartIndex;
    return GestureDetector(
      onTap: () => setState(() => _currentCartIndex = index),
      child: Container(
        margin: const EdgeInsets.only(right: 8),
        padding: EdgeInsets.symmetric(
          horizontal: isActive ? 14 : 10,
          vertical: isActive ? 10 : 8,
        ),
        decoration: BoxDecoration(
          color: isActive ? scheme.primary : Colors.grey.shade100,
          borderRadius: BorderRadius.circular(10),
          border: isActive
              ? Border.all(color: scheme.primary.withOpacity(0.92), width: 2)
              : Border.all(color: Colors.grey.shade300, width: 1),
          boxShadow: isActive
              ? [
                  BoxShadow(
                    color: scheme.primary.withOpacity(0.3),
                    blurRadius: 6,
                    offset: const Offset(0, 2),
                  ),
                ]
              : null,
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Icono de check solo para el ticket activo
            if (isActive)
              const Padding(
                padding: EdgeInsets.only(right: 6),
                child: Icon(
                  Icons.check_circle_outline,
                  size: 18,
                  color: Colors.white,
                ),
              ),
            // Botón de editar nombre (solo ticket activo sin cliente)
            if (isActive && cart.selectedClient == null)
              InkWell(
                onTap: () => _renameTicket(index),
                child: const Padding(
                  padding: EdgeInsets.only(right: 4),
                  child: Icon(Icons.edit, size: 14, color: Colors.white70),
                ),
              ),
            Text(
              cart.displayName,
              style: TextStyle(
                color: isActive ? Colors.white : Colors.grey.shade700,
                fontSize: isActive ? 14 : 12,
                fontWeight: isActive ? FontWeight.bold : FontWeight.normal,
              ),
            ),
            if (cart.items.isNotEmpty)
              Container(
                margin: const EdgeInsets.only(left: 8),
                padding: const EdgeInsets.all(5),
                decoration: BoxDecoration(
                  color: isActive ? Colors.white : scheme.primary,
                  shape: BoxShape.circle,
                ),
                child: Text(
                  '${cart.items.length}',
                  style: TextStyle(
                    color: isActive ? scheme.primary : Colors.white,
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            if (_carts.length > 1 && isActive)
              InkWell(
                onTap: () => _deleteTicket(index),
                child: const Padding(
                  padding: EdgeInsets.only(left: 8),
                  child: Icon(Icons.close, size: 16, color: Colors.white70),
                ),
              ),
          ],
        ),
      ),
    );
  }

  /// Construye la barra mejorada de tickets pendientes con contador y selector
  Widget _buildPendingTicketsBar() {
    final totalTickets = _carts.length;
    final activeCart = _currentCart;

    return Row(
      children: [
        // Badge contador de tickets pendientes
        Tooltip(
          message:
              '$totalTickets ticket${totalTickets > 1 ? 's' : ''} pendiente${totalTickets > 1 ? 's' : ''}',
          child: Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [scheme.primary.withOpacity(0.85), scheme.primary.withOpacity(0.45)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: scheme.primary.withOpacity(0.3),
                  blurRadius: 4,
                  offset: const Offset(0, 2),
                ),
              ],
            ),
            child: Text(
              '$totalTickets',
              style: const TextStyle(
                color: Colors.white,
                fontSize: 13,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ),
        const SizedBox(width: 12),
        // Comportamiento diferente según cantidad de tickets
        if (totalTickets <= 2)
          Expanded(
            child: SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              child: Row(
                children: _carts
                    .asMap()
                    .entries
                    .map((e) => _buildCartTab(e.key, e.value))
                    .toList(),
              ),
            ),
          )
        else
          Expanded(
            child: Material(
              color: Colors.transparent,
              child: InkWell(
                onTap: () => _showTicketSelector(),
                borderRadius: BorderRadius.circular(10),
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 14,
                    vertical: 10,
                  ),
                  decoration: BoxDecoration(
                    color: scheme.primary,
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: scheme.primary.withOpacity(0.92), width: 2),
                    boxShadow: [
                      BoxShadow(
                        color: scheme.primary.withOpacity(0.3),
                        blurRadius: 6,
                        offset: const Offset(0, 2),
                      ),
                    ],
                  ),
                  child: Row(
                    children: [
                      const Icon(
                        Icons.check_circle_outline,
                        size: 18,
                        color: Colors.white,
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          activeCart.displayName,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 14,
                            fontWeight: FontWeight.bold,
                          ),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 6,
                          vertical: 2,
                        ),
                        decoration: BoxDecoration(
                          color: Colors.white.withOpacity(0.2),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              '$totalTickets',
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 11,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                            const SizedBox(width: 2),
                            const Icon(
                              Icons.arrow_drop_down,
                              color: Colors.white,
                              size: 18,
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        const SizedBox(width: 8),
        // Botón para agregar nuevo ticket
        Container(
          decoration: BoxDecoration(
            color: scheme.primary.withOpacity(0.08),
            shape: BoxShape.circle,
          ),
          child: IconButton(
            icon: Icon(Icons.add_circle, color: scheme.primary.withOpacity(0.85), size: 28),
            onPressed: _addNewTicket,
            tooltip: 'Nuevo ticket',
          ),
        ),
      ],
    );
  }

  /// Abre un selector modal con la lista de tickets pendientes
  Future<void> _showTicketSelector() async {
    final selected = await showModalBottomSheet<int>(
      context: context,
      builder: (context) => Container(
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: const BorderRadius.vertical(top: Radius.circular(16)),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Header del modal
            Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  const Text(
                    'Tickets Pendientes',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                  const Spacer(),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
            ),
            const Divider(height: 1),
            // Lista de tickets
            Flexible(
              child: ListView.builder(
                itemCount: _carts.length,
                itemBuilder: (context, index) {
                  final cart = _carts[index];
                  final isActive = index == _currentCartIndex;
                  return Container(
                    margin: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 2,
                    ),
                    decoration: BoxDecoration(
                      color: isActive
                          ? scheme.primary.withOpacity(0.08)
                          : Colors.transparent,
                      borderRadius: BorderRadius.circular(8),
                      border: isActive
                          ? Border.all(color: scheme.primary.withOpacity(0.22), width: 1)
                          : null,
                    ),
                    child: ListTile(
                      leading: isActive
                          ? Icon(Icons.check_circle, color: scheme.primary)
                          : Icon(
                              Icons.radio_button_unchecked,
                              color: Colors.grey.shade400,
                            ),
                      title: Text(
                        cart.displayName,
                        style: TextStyle(
                          fontWeight: isActive
                              ? FontWeight.bold
                              : FontWeight.normal,
                          fontSize: isActive ? 15 : 14,
                          color: isActive
                              ? scheme.primary.withOpacity(0.92)
                              : Colors.black87,
                        ),
                      ),
                      subtitle: Text(
                        cart.items.isEmpty
                            ? 'Sin items'
                            : '${cart.items.length} item${cart.items.length > 1 ? 's' : ''} - RD\$${cart.calculateTotal().toStringAsFixed(2)}',
                        style: TextStyle(
                          color: Colors.grey.shade600,
                          fontSize: 12,
                        ),
                      ),
                      trailing: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          if (cart.items.isNotEmpty)
                            Container(
                              padding: const EdgeInsets.all(6),
                              margin: const EdgeInsets.only(right: 8),
                              decoration: BoxDecoration(
                                color: isActive
                                    ? scheme.primary
                                    : Colors.grey.shade200,
                                shape: BoxShape.circle,
                              ),
                              child: Text(
                                '${cart.items.length}',
                                style: TextStyle(
                                  color: isActive
                                      ? Colors.white
                                      : Colors.grey.shade700,
                                  fontSize: 12,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          // Botón de eliminar
                          if (_carts.length > 1)
                            IconButton(
                              icon: const Icon(
                                Icons.delete_outline,
                                color: Colors.red,
                              ),
                              iconSize: 20,
                              onPressed: () {
                                Navigator.pop(context);
                                _deleteTicket(index);
                              },
                              tooltip: 'Eliminar ticket',
                            ),
                        ],
                      ),
                      onTap: () => Navigator.pop(context, index),
                    ),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );

    // Si el usuario selecciona un ticket, cambiar al ticket activo
    if (selected != null) {
      setState(() => _currentCartIndex = selected);
    }
  }

  Future<void> _renameTicket(int index) async {
    final result = await showDialog<String>(
      context: context,
      builder: (context) => TicketRenameDialog(currentName: _carts[index].name),
    );

    if (result != null && result.trim().isNotEmpty) {
      setState(() => _carts[index].name = result.trim());
      if (_carts[index].ticketId != null) {
        await TicketsRepository().updateTicketName(
          _carts[index].ticketId!,
          result.trim(),
        );
      }
    }
  }

  Future<void> _deleteTicket(int index) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Eliminar Ticket'),
        content: Text('¿Seguro que deseas eliminar "${_carts[index].name}"?'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancelar'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            child: const Text('Eliminar'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      if (_carts[index].ticketId != null) {
        await TicketsRepository().deleteTicket(_carts[index].ticketId!);
      }

      setState(() {
        _carts.removeAt(index);
        if (_currentCartIndex >= _carts.length) {
          _currentCartIndex = _carts.length - 1;
        }
      });

      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Ticket eliminado')));
    }
  }
}

class _Cart {
  String name;
  int? ticketId;
  int? tempCartId; // ID del carrito temporal en la base de datos
  bool isCompleted = false; // Marca si la venta fue completada
  final List<SaleItemModel> items = [];
  double discount = 0.0;
  bool itbisEnabled = true;
  double itbisRate = 0.18;
  bool fiscalEnabled = false;
  NcfBookModel? selectedNcf;
  ClientModel? selectedClient;

  String? discountTotalType;
  double? discountTotalValue;

  _Cart({required this.name});

  /// Nombre limpio para mostrar en la UI (elimina "(Copia)" repetidos)
  String get displayName {
    // Si tiene cliente seleccionado, usar nombre del cliente con formato limpio
    if (selectedClient != null) {
      final clientName = selectedClient!.nombre.trim();
      // Si el ticketId existe, usar un formato tipo "Ticket X - Cliente"
      if (ticketId != null) {
        return 'Ticket $ticketId - $clientName';
      }
      return clientName;
    }

    // Limpiar nombre eliminando "(Copia)" repetidos
    String cleanName = name;

    // Remover múltiples "(Copia)" y dejar solo uno si existe
    final copiaRegex = RegExp(r'\s*\(Copia\)', caseSensitive: false);
    final hasCopia = copiaRegex.hasMatch(cleanName);
    cleanName = cleanName.replaceAll(copiaRegex, '').trim();

    // Si tenía (Copia), agregar solo uno
    if (hasCopia) {
      cleanName = '$cleanName (Copia)';
    }

    // Si el nombre está muy largo, truncar
    if (cleanName.length > 25) {
      cleanName = '${cleanName.substring(0, 22)}...';
    }

    return cleanName;
  }

  void addProduct(ProductModel product) {
    final existingIndex = items.indexWhere(
      (item) => item.productId == product.id,
    );
    if (existingIndex >= 0) {
      items[existingIndex] = items[existingIndex].copyWith(
        qty: items[existingIndex].qty + 1,
      );
    } else {
      final now = DateTime.now().millisecondsSinceEpoch;
      items.add(
        SaleItemModel(
          id: null,
          saleId: 0,
          productId: product.id,
          productCodeSnapshot: product.code,
          productNameSnapshot: product.name,
          qty: 1,
          unitPrice: product.salePrice,
          discountLine: 0.0,
          purchasePriceSnapshot: product.purchasePrice,
          totalLine: product.salePrice,
          createdAtMs: now,
        ),
      );
    }
  }

  double getQuantityForProduct(int productId) {
    double total = 0.0;
    for (final item in items) {
      if (item.productId == productId) total += item.qty;
    }
    return total;
  }

  void updateQuantity(int index, double newQty) {
    if (index >= 0 && index < items.length)
      items[index] = items[index].copyWith(qty: newQty);
  }

  void removeItem(int index) {
    if (index >= 0 && index < items.length) items.removeAt(index);
  }

  void clear() {
    items.clear();
    discount = 0.0;
    discountTotalType = null;
    discountTotalValue = null;
    selectedClient = null;
    selectedNcf = null;
  }

  double calculateGrossSubtotal() {
    double subtotal = 0.0;
    for (var item in items) {
      subtotal += item.qty * item.unitPrice;
    }
    return subtotal;
  }

  double calculateLineDiscounts() {
    double total = 0.0;
    for (var item in items) {
      total += item.discountLine;
    }
    return total;
  }

  double calculateSubtotal() {
    return calculateGrossSubtotal() - calculateLineDiscounts() - discount;
  }

  double calculateTotalDiscount() {
    if (discountTotalValue == null || discountTotalValue! <= 0) return 0.0;
    final subtotal = calculateSubtotal();
    if (discountTotalType == 'percent')
      return subtotal * (discountTotalValue! / 100);
    return discountTotalValue!;
  }

  double calculateSubtotalAfterDiscount() {
    return (calculateSubtotal() - calculateTotalDiscount()).clamp(
      0.0,
      double.infinity,
    );
  }

  double calculateTotalDiscountsCombined() {
    final total =
        calculateLineDiscounts() + discount + calculateTotalDiscount();
    return total.clamp(0.0, double.infinity);
  }

  double calculateItbis() =>
      itbisEnabled ? calculateSubtotalAfterDiscount() * itbisRate : 0.0;

  double calculateTotal() =>
      calculateSubtotalAfterDiscount() + calculateItbis();
}

// ---- Shortcut intents ----------------------------------------------------
class FocusSearchProductIntent extends Intent {
  const FocusSearchProductIntent();
}

class FocusSearchClientIntent extends Intent {
  const FocusSearchClientIntent();
}

class NewClientIntent extends Intent {
  const NewClientIntent();
}

class ApplyDiscountIntent extends Intent {
  const ApplyDiscountIntent();
}

class OpenPaymentIntent extends Intent {
  const OpenPaymentIntent();
}

class FinalizeSaleIntent extends Intent {
  const FinalizeSaleIntent();
}

class DeleteSelectedItemIntent extends Intent {
  const DeleteSelectedItemIntent();
}

class IncreaseQuantityIntent extends Intent {
  const IncreaseQuantityIntent();
}

class DecreaseQuantityIntent extends Intent {
  const DecreaseQuantityIntent();
}
