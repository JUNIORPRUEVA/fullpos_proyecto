import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:intl/intl.dart';
import '../../../../core/constants/app_colors.dart';
import '../../../../core/errors/error_handler.dart';

import '../../../clients/data/client_model.dart';
import '../../../clients/data/clients_repository.dart';
import '../../../clients/ui/client_form_dialog.dart';
import '../../data/loan_models.dart';
import '../../data/loans_calculator.dart';
import '../../data/loans_repository.dart';

/// Diálogo para crear un nuevo préstamo
class LoanFormDialog extends StatefulWidget {
  const LoanFormDialog({super.key});

  @override
  State<LoanFormDialog> createState() => _LoanFormDialogState();
}

class _LoanFormDialogState extends State<LoanFormDialog> {
  final _formKey = GlobalKey<FormState>();

  // Controllers
  final _principalController = TextEditingController();
  final _interestRateController = TextEditingController(text: '10');
  final _installmentsController = TextEditingController(text: '4');
  final _lateFeeController = TextEditingController(text: '0');
  final _noteController = TextEditingController();
  final _collateralDescController = TextEditingController();
  final _collateralValueController = TextEditingController();
  final _collateralSerialController = TextEditingController();

  // State
  List<ClientModel> _clients = [];
  ClientModel? _selectedClient;
  String _loanType = LoanType.unsecured;
  String _interestMode = InterestMode.interestPerInstallment;
  String _frequency = LoanFrequency.monthly;
  DateTime _startDate = DateTime.now();
  bool _startDateManuallySet = false;
  bool _isLoading = false;
  bool _isLoadingClients = true;

  // Calculados
  double _totalDue = 0;
  double _monthlyPayment = 0;

  @override
  void initState() {
    super.initState();
    _startDate = _defaultFirstInstallmentDateFor(_frequency);
    _loadClients();
    _principalController.addListener(_recalculate);
    _interestRateController.addListener(_recalculate);
    _installmentsController.addListener(_recalculate);
  }

  DateTime _defaultFirstInstallmentDateFor(String frequency) {
    final now = DateTime.now();
    final next = LoansCalculator.nextDueDate(now, frequency);
    // Para frecuencia "Pago Único", el vencimiento por defecto es hoy.
    if (frequency == LoanFrequency.single) return _normalizeDueDate(now);
    return next.isBefore(now) ? _normalizeDueDate(now) : next;
  }

  DateTime _normalizeDueDate(DateTime date) {
    // Si viene sin hora (00:00:00.000), lo ponemos a final de día
    // para evitar que quede vencido el mismo día.
    final isMidnight =
        date.hour == 0 &&
        date.minute == 0 &&
        date.second == 0 &&
        date.millisecond == 0 &&
        date.microsecond == 0;
    if (!isMidnight) return date;
    return DateTime(date.year, date.month, date.day, 23, 59, 59, 999);
  }

  @override
  void dispose() {
    _principalController.dispose();
    _interestRateController.dispose();
    _installmentsController.dispose();
    _lateFeeController.dispose();
    _noteController.dispose();
    _collateralDescController.dispose();
    _collateralValueController.dispose();
    _collateralSerialController.dispose();
    super.dispose();
  }

  Future<void> _loadClients() async {
    try {
      final clients = await ClientsRepository.list(isActive: true);
      setState(() {
        _clients = clients;
        _isLoadingClients = false;
      });
    } catch (e) {
      setState(() => _isLoadingClients = false);
    }
  }

  Future<void> _createClientFromLoan() async {
    if (_isLoading) return;

    final created = await showDialog<ClientModel>(
      context: context,
      barrierDismissible: false,
      builder: (context) => const ClientFormDialog(),
    );

    if (created == null) return;

    // Refrescar lista (por si reactivó un cliente inactivo o creó uno nuevo).
    await _loadClients();

    if (!mounted) return;
    setState(() {
      _selectedClient = _clients.firstWhere(
        (c) => c.id == created.id,
        orElse: () => created,
      );
    });
  }

  void _recalculate() {
    final principal = double.tryParse(_principalController.text) ?? 0;
    final rate = double.tryParse(_interestRateController.text) ?? 0;
    final installments = int.tryParse(_installmentsController.text) ?? 1;

    if (principal > 0 && installments > 0) {
      final total = LoansCalculator.computeTotalDue(
        principal: principal,
        interestRate: rate,
        interestMode: _interestMode,
        installmentsCount: installments,
        frequency: _frequency,
      );
      setState(() {
        _totalDue = total;
        _monthlyPayment = total / installments;
      });
    }
  }

  Future<void> _selectDate() async {
    final date = await showDatePicker(
      context: context,
      initialDate: DateTime(_startDate.year, _startDate.month, _startDate.day),
      firstDate: DateTime.now().subtract(const Duration(days: 30)),
      lastDate: DateTime.now().add(const Duration(days: 365)),
    );
    if (date != null) {
      setState(() {
        _startDateManuallySet = true;
        _startDate = _normalizeDueDate(date);
      });
    }
  }

  Future<void> _save() async {
    if (!_formKey.currentState!.validate()) return;
    if (_selectedClient == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Seleccione un cliente'),
          backgroundColor: AppColors.error,
        ),
      );
      return;
    }

    setState(() => _isLoading = true);

    try {
      final normalizedStartDate = _normalizeDueDate(_startDate);
      final dto = CreateLoanDto(
        clientId: _selectedClient!.id!,
        type: _loanType,
        principal: double.parse(_principalController.text),
        interestRate: double.parse(_interestRateController.text),
        interestMode: _interestMode,
        frequency: _frequency,
        installmentsCount: int.parse(_installmentsController.text),
        startDate: normalizedStartDate,
        lateFee: double.tryParse(_lateFeeController.text) ?? 0,
        note: _noteController.text.isEmpty ? null : _noteController.text,
        collateralDescription: _loanType == LoanType.secured
            ? _collateralDescController.text
            : null,
        collateralValue: _loanType == LoanType.secured
            ? double.tryParse(_collateralValueController.text)
            : null,
        collateralSerial: _loanType == LoanType.secured
            ? _collateralSerialController.text
            : null,
        collateralCondition: null,
      );

      await LoansRepository.createLoan(dto);

      if (mounted) {
        Navigator.pop(context, true);
      }
    } catch (e, st) {
      setState(() => _isLoading = false);
      if (mounted) {
        await ErrorHandler.instance.handle(
          e,
          stackTrace: st,
          context: context,
          onRetry: _save,
          module: 'loans/create',
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final currencyFormat = NumberFormat.currency(
      locale: 'es_DO',
      symbol: 'RD\$',
    );
    final dateFormat = DateFormat('dd/MM/yyyy');

    return Dialog(
      child: Container(
        constraints: const BoxConstraints(maxWidth: 600, maxHeight: 700),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Header
            Container(
              padding: const EdgeInsets.all(16),
              decoration: const BoxDecoration(
                color: AppColors.teal800,
                borderRadius: BorderRadius.only(
                  topLeft: Radius.circular(12),
                  topRight: Radius.circular(12),
                ),
              ),
              child: Row(
                children: [
                  const Icon(Icons.add_card, color: Colors.white, size: 24),
                  const SizedBox(width: 12),
                  const Expanded(
                    child: Text(
                      'Nuevo Préstamo',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                  IconButton(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.close, color: Colors.white),
                  ),
                ],
              ),
            ),

            // Form
            Flexible(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(16),
                child: Form(
                  key: _formKey,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Cliente
                      const Text(
                        'Cliente *',
                        style: TextStyle(
                          fontWeight: FontWeight.w600,
                          fontSize: 13,
                        ),
                      ),
                      const SizedBox(height: 6),
                      _isLoadingClients
                          ? const LinearProgressIndicator()
                          : Row(
                              children: [
                                Expanded(
                                  child: DropdownButtonFormField<ClientModel>(
                                    value: _selectedClient,
                                    hint: const Text('Seleccionar cliente'),
                                    isExpanded: true,
                                    decoration: const InputDecoration(
                                      prefixIcon: Icon(
                                        Icons.person_outline,
                                        size: 20,
                                      ),
                                      contentPadding: EdgeInsets.symmetric(
                                        horizontal: 12,
                                        vertical: 12,
                                      ),
                                    ),
                                    items: _clients
                                        .map(
                                          (c) => DropdownMenuItem(
                                            value: c,
                                            child: Text(
                                              c.nombre,
                                              overflow: TextOverflow.ellipsis,
                                            ),
                                          ),
                                        )
                                        .toList(),
                                    onChanged: (v) =>
                                        setState(() => _selectedClient = v),
                                    validator: (v) =>
                                        v == null ? 'Requerido' : null,
                                  ),
                                ),
                                const SizedBox(width: 10),
                                OutlinedButton.icon(
                                  onPressed: _isLoading
                                      ? null
                                      : _createClientFromLoan,
                                  icon: const Icon(Icons.person_add_alt_1),
                                  label: const Text('Nuevo'),
                                ),
                              ],
                            ),

                      const SizedBox(height: 16),

                      // Tipo de préstamo
                      const Text(
                        'Tipo de Préstamo',
                        style: TextStyle(
                          fontWeight: FontWeight.w600,
                          fontSize: 13,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Row(
                        children: [
                          Expanded(
                            child: _TypeCard(
                              title: 'Sin Garantía',
                              icon: Icons.person,
                              isSelected: _loanType == LoanType.unsecured,
                              onTap: () => setState(
                                () => _loanType = LoanType.unsecured,
                              ),
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: _TypeCard(
                              title: 'Con Garantía',
                              icon: Icons.inventory_2,
                              isSelected: _loanType == LoanType.secured,
                              onTap: () =>
                                  setState(() => _loanType = LoanType.secured),
                            ),
                          ),
                        ],
                      ),

                      const SizedBox(height: 16),

                      // Monto y tasa
                      Row(
                        children: [
                          Expanded(
                            flex: 2,
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(
                                  'Monto Principal *',
                                  style: TextStyle(
                                    fontWeight: FontWeight.w600,
                                    fontSize: 13,
                                  ),
                                ),
                                const SizedBox(height: 6),
                                TextFormField(
                                  controller: _principalController,
                                  keyboardType:
                                      const TextInputType.numberWithOptions(
                                        decimal: true,
                                      ),
                                  inputFormatters: [
                                    FilteringTextInputFormatter.allow(
                                      RegExp(r'[\d.]'),
                                    ),
                                  ],
                                  decoration: const InputDecoration(
                                    prefixText: 'RD\$ ',
                                    hintText: '0.00',
                                  ),
                                  validator: (v) {
                                    if (v == null || v.isEmpty)
                                      return 'Requerido';
                                    final val = double.tryParse(v);
                                    if (val == null || val <= 0)
                                      return 'Monto inválido';
                                    return null;
                                  },
                                ),
                              ],
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(
                                  'Tasa %',
                                  style: TextStyle(
                                    fontWeight: FontWeight.w600,
                                    fontSize: 13,
                                  ),
                                ),
                                const SizedBox(height: 6),
                                TextFormField(
                                  controller: _interestRateController,
                                  keyboardType:
                                      const TextInputType.numberWithOptions(
                                        decimal: true,
                                      ),
                                  inputFormatters: [
                                    FilteringTextInputFormatter.allow(
                                      RegExp(r'[\d.]'),
                                    ),
                                  ],
                                  decoration: const InputDecoration(
                                    suffixText: '%',
                                    hintText: '10',
                                  ),
                                  validator: (v) {
                                    if (v == null || v.trim().isEmpty) {
                                      return 'Requerido';
                                    }
                                    final val = double.tryParse(v.trim());
                                    if (val == null || val < 0) {
                                      return 'Inválido';
                                    }
                                    return null;
                                  },
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),

                      const SizedBox(height: 16),

                      // Modo de interés
                      const Text(
                        'Modo de Interés',
                        style: TextStyle(
                          fontWeight: FontWeight.w600,
                          fontSize: 13,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Row(
                        children: [
                          Expanded(
                            child: RadioListTile<String>(
                              title: const Text(
                                'Por Cuota',
                                style: TextStyle(fontSize: 13),
                              ),
                              subtitle: const Text(
                                '% × cada cuota',
                                style: TextStyle(fontSize: 11),
                              ),
                              value: InterestMode.interestPerInstallment,
                              groupValue: _interestMode,
                              onChanged: (v) {
                                setState(() => _interestMode = v!);
                                _recalculate();
                              },
                              contentPadding: EdgeInsets.zero,
                              dense: true,
                            ),
                          ),
                          Expanded(
                            child: RadioListTile<String>(
                              title: const Text(
                                'Interés Fijo',
                                style: TextStyle(fontSize: 13),
                              ),
                              subtitle: const Text(
                                '% una sola vez',
                                style: TextStyle(fontSize: 11),
                              ),
                              value: InterestMode.fixedInterest,
                              groupValue: _interestMode,
                              onChanged: (v) {
                                setState(() => _interestMode = v!);
                                _recalculate();
                              },
                              contentPadding: EdgeInsets.zero,
                              dense: true,
                            ),
                          ),
                        ],
                      ),

                      const SizedBox(height: 16),

                      // Frecuencia y cuotas
                      Row(
                        children: [
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(
                                  'Frecuencia',
                                  style: TextStyle(
                                    fontWeight: FontWeight.w600,
                                    fontSize: 13,
                                  ),
                                ),
                                const SizedBox(height: 6),
                                DropdownButtonFormField<String>(
                                  value: _frequency,
                                  decoration: const InputDecoration(
                                    contentPadding: EdgeInsets.symmetric(
                                      horizontal: 12,
                                      vertical: 12,
                                    ),
                                  ),
                                  items: const [
                                    DropdownMenuItem(
                                      value: LoanFrequency.weekly,
                                      child: Text('Semanal'),
                                    ),
                                    DropdownMenuItem(
                                      value: LoanFrequency.biweekly,
                                      child: Text('Quincenal'),
                                    ),
                                    DropdownMenuItem(
                                      value: LoanFrequency.monthly,
                                      child: Text('Mensual'),
                                    ),
                                    DropdownMenuItem(
                                      value: LoanFrequency.single,
                                      child: Text('Pago Único'),
                                    ),
                                  ],
                                  onChanged: (v) {
                                    setState(() {
                                      _frequency = v!;
                                      if (!_startDateManuallySet) {
                                        _startDate =
                                            _defaultFirstInstallmentDateFor(
                                              _frequency,
                                            );
                                      }
                                    });
                                    _recalculate();
                                  },
                                ),
                              ],
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(
                                  'Cuotas',
                                  style: TextStyle(
                                    fontWeight: FontWeight.w600,
                                    fontSize: 13,
                                  ),
                                ),
                                const SizedBox(height: 6),
                                TextFormField(
                                  controller: _installmentsController,
                                  keyboardType: TextInputType.number,
                                  inputFormatters: [
                                    FilteringTextInputFormatter.digitsOnly,
                                  ],
                                  decoration: const InputDecoration(
                                    hintText: '4',
                                  ),
                                  validator: (v) {
                                    if (v == null || v.isEmpty)
                                      return 'Requerido';
                                    final val = int.tryParse(v);
                                    if (val == null || val <= 0)
                                      return 'Inválido';
                                    return null;
                                  },
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),

                      const SizedBox(height: 16),

                      // Fecha inicio
                      Row(
                        children: [
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(
                                  'Fecha Primera Cuota',
                                  style: TextStyle(
                                    fontWeight: FontWeight.w600,
                                    fontSize: 13,
                                  ),
                                ),
                                const SizedBox(height: 6),
                                InkWell(
                                  onTap: _selectDate,
                                  child: Container(
                                    padding: const EdgeInsets.symmetric(
                                      horizontal: 12,
                                      vertical: 14,
                                    ),
                                    decoration: BoxDecoration(
                                      border: Border.all(
                                        color: Colors.grey.shade300,
                                      ),
                                      borderRadius: BorderRadius.circular(8),
                                    ),
                                    child: Row(
                                      children: [
                                        const Icon(
                                          Icons.calendar_today,
                                          size: 18,
                                          color: Colors.grey,
                                        ),
                                        const SizedBox(width: 8),
                                        Text(dateFormat.format(_startDate)),
                                      ],
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(
                                  'Mora por atraso',
                                  style: TextStyle(
                                    fontWeight: FontWeight.w600,
                                    fontSize: 13,
                                  ),
                                ),
                                const SizedBox(height: 6),
                                TextFormField(
                                  controller: _lateFeeController,
                                  keyboardType:
                                      const TextInputType.numberWithOptions(
                                        decimal: true,
                                      ),
                                  inputFormatters: [
                                    FilteringTextInputFormatter.allow(
                                      RegExp(r'[\d.]'),
                                    ),
                                  ],
                                  decoration: const InputDecoration(
                                    prefixText: 'RD\$ ',
                                    hintText: '0',
                                  ),
                                  validator: (v) {
                                    if (v == null || v.trim().isEmpty) {
                                      return 'Requerido';
                                    }
                                    final val = double.tryParse(v.trim());
                                    if (val == null || val < 0) {
                                      return 'Inválido';
                                    }
                                    return null;
                                  },
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),

                      // Garantía (si aplica)
                      if (_loanType == LoanType.secured) ...[
                        const SizedBox(height: 20),
                        Container(
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: AppColors.gold.withOpacity(0.1),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(
                              color: AppColors.gold.withOpacity(0.3),
                            ),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                children: [
                                  Icon(
                                    Icons.inventory_2,
                                    color: AppColors.gold,
                                    size: 18,
                                  ),
                                  const SizedBox(width: 8),
                                  const Text(
                                    'Datos de Garantía',
                                    style: TextStyle(
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 12),
                              TextFormField(
                                controller: _collateralDescController,
                                decoration: const InputDecoration(
                                  labelText: 'Descripción del artículo *',
                                  hintText: 'Ej: Laptop HP...',
                                ),
                                validator: _loanType == LoanType.secured
                                    ? (v) => v == null || v.trim().isEmpty
                                          ? 'Requerido'
                                          : null
                                    : null,
                              ),
                              const SizedBox(height: 12),
                              Row(
                                children: [
                                  Expanded(
                                    child: TextFormField(
                                      controller: _collateralValueController,
                                      keyboardType:
                                          const TextInputType.numberWithOptions(
                                            decimal: true,
                                          ),
                                      decoration: const InputDecoration(
                                        labelText: 'Valor estimado',
                                        prefixText: 'RD\$ ',
                                      ),
                                    ),
                                  ),
                                  const SizedBox(width: 12),
                                  Expanded(
                                    child: TextFormField(
                                      controller: _collateralSerialController,
                                      decoration: const InputDecoration(
                                        labelText: 'Serial/IMEI',
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                            ],
                          ),
                        ),
                      ],

                      const SizedBox(height: 16),

                      // Notas
                      TextFormField(
                        controller: _noteController,
                        maxLines: 2,
                        decoration: const InputDecoration(
                          labelText: 'Notas (opcional)',
                          hintText: 'Observaciones adicionales...',
                        ),
                      ),

                      const SizedBox(height: 20),

                      // Resumen
                      Container(
                        padding: const EdgeInsets.all(16),
                        decoration: BoxDecoration(
                          color: AppColors.teal.withOpacity(0.05),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(
                            color: AppColors.teal.withOpacity(0.2),
                          ),
                        ),
                        child: Column(
                          children: [
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                const Text(
                                  'Total a Pagar:',
                                  style: TextStyle(fontSize: 14),
                                ),
                                Text(
                                  currencyFormat.format(_totalDue),
                                  style: const TextStyle(
                                    fontSize: 18,
                                    fontWeight: FontWeight.bold,
                                    color: AppColors.teal700,
                                  ),
                                ),
                              ],
                            ),
                            const Divider(height: 16),
                            Row(
                              mainAxisAlignment: MainAxisAlignment.spaceBetween,
                              children: [
                                Text(
                                  'Cuota ${_getFrequencyLabel()}:',
                                  style: const TextStyle(fontSize: 14),
                                ),
                                Text(
                                  currencyFormat.format(_monthlyPayment),
                                  style: const TextStyle(
                                    fontSize: 16,
                                    fontWeight: FontWeight.w600,
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
              ),
            ),

            // Actions
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.grey.shade50,
                border: Border(top: BorderSide(color: Colors.grey.shade200)),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: () => Navigator.pop(context),
                      child: const Text('Cancelar'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    flex: 2,
                    child: ElevatedButton.icon(
                      onPressed: _isLoading ? null : _save,
                      icon: _isLoading
                          ? const SizedBox(
                              width: 18,
                              height: 18,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                color: Colors.white,
                              ),
                            )
                          : const Icon(Icons.check),
                      label: Text(
                        _isLoading ? 'Guardando...' : 'Crear Préstamo',
                      ),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.teal,
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                      ),
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

  String _getFrequencyLabel() {
    switch (_frequency) {
      case LoanFrequency.weekly:
        return 'Semanal';
      case LoanFrequency.biweekly:
        return 'Quincenal';
      case LoanFrequency.monthly:
        return 'Mensual';
      case LoanFrequency.single:
        return 'Única';
      default:
        return '';
    }
  }
}

class _TypeCard extends StatelessWidget {
  final String title;
  final IconData icon;
  final bool isSelected;
  final VoidCallback onTap;

  const _TypeCard({
    required this.title,
    required this.icon,
    required this.isSelected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: isSelected
              ? AppColors.teal.withOpacity(0.1)
              : Colors.grey.shade50,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: isSelected ? AppColors.teal : Colors.grey.shade300,
            width: isSelected ? 2 : 1,
          ),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              icon,
              size: 20,
              color: isSelected ? AppColors.teal : Colors.grey,
            ),
            const SizedBox(width: 8),
            Text(
              title,
              style: TextStyle(
                fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                color: isSelected ? AppColors.teal : Colors.grey.shade700,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
