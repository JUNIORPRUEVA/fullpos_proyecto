/// Ejemplo de cómo integrar las configuraciones en el módulo de préstamos
/// Este archivo muestra cómo usar el servicio de configuración en cálculos reales
/// 
/// ⚠️ NOTA: Este es un archivo de DOCUMENTACIÓN/EJEMPLO
/// Los códigos aquí son ejemplos que puedes adaptar en tus archivos reales.
///

/*
import 'package:your_app/core/services/app_configuration_service.dart';
import 'package:your_app/core/helpers/business_config_helper.dart';

class LoanCalculationExample {
  
  /// Ejemplo 1: Crear un nuevo préstamo usando configuraciones por defecto
  static void createNewLoan(double amount) {
    // Obtener configuraciones por defecto
    double interestRate = appConfigService.getDefaultInterestRate();
    int loanTermDays = appConfigService.getDefaultLoanTermDays();
    int gracePeriod = appConfigService.getGracePeriodDays();
    
    // Calcular interés
    double interest = BusinessConfigHelper.calculateSimpleInterest(
      amount: amount,
      days: loanTermDays,
    );
    
    double totalAmount = amount + interest;
    
    print('''
    NUEVO PRÉSTAMO
    ===============
    Monto: ${appConfigService.formatCurrency(amount)}
    Tasa de Interés: ${interestRate}%
    Plazo: $loanTermDays días (${BusinessConfigHelper.getDefaultLoanTermText()})
    Período de Gracia: $gracePeriod días
    Interés: ${appConfigService.formatCurrency(interest)}
    Total a Pagar: ${appConfigService.formatCurrency(totalAmount)}
    ''');
  }

  /// Ejemplo 2: Calcular mora por atraso en pago
  static void calculateLateFeeExample(double loanAmount, int daysOverdue) {
    double lateFee = BusinessConfigHelper.calculateLateFee(
      originalAmount: loanAmount,
      daysOverdue: daysOverdue,
    );
    
    int graceDays = appConfigService.getGracePeriodDays();
    int effectiveDaysOverdue = (daysOverdue - graceDays).clamp(0, daysOverdue);
    
    print('''
    CÁLCULO DE MORA
    ===============
    Monto Préstamo: ${appConfigService.formatCurrency(loanAmount)}
    Días de Atraso: $daysOverdue
    Período de Gracia: $graceDays días
    Días Efectivos de Atraso: $effectiveDaysOverdue
    Tasa de Mora: ${appConfigService.getDefaultLateFeeRate()}%
    Mora Calculada: ${appConfigService.formatCurrency(lateFee)}
    Monto Total a Pagar: ${appConfigService.formatCurrency(loanAmount + lateFee)}
    ''');
  }

  /// Ejemplo 3: Calcular cuota mensual
  static void calculateMonthlyPaymentExample(double amount, int months) {
    double monthlyPayment = BusinessConfigHelper.calculateMonthlyPayment(
      amount: amount,
      monthsCount: months,
    );
    
    double totalToPay = monthlyPayment * months;
    double totalInterest = totalToPay - amount;
    
    print('''
    CÁLCULO DE CUOTA MENSUAL
    ========================
    Monto del Préstamo: ${appConfigService.formatCurrency(amount)}
    Plazo: $months meses
    Tasa Anual: ${appConfigService.getDefaultInterestRate()}%
    Cuota Mensual: ${appConfigService.formatCurrency(monthlyPayment)}
    Total Interés: ${appConfigService.formatCurrency(totalInterest)}
    Total a Pagar: ${appConfigService.formatCurrency(totalToPay)}
    ''');
  }

  /// Ejemplo 4: Generar recibo de préstamo
  static String generateLoanReceipt(String clientName, double amount) {
    final config = appConfigService;
    final businessInfo = config.getFormattedBusinessInfo();
    final timestamp = DateTime.now();
    
    return '''
╔════════════════════════════════════════╗
║  ${config.getBusinessName()}
║  ${config.getSlogan() ?? ''}
╚════════════════════════════════════════╝

RECIBO DE PRÉSTAMO

Fecha: $timestamp
Cliente: $clientName

─────────────────────────────────────────

Monto del Préstamo:    ${config.formatCurrency(amount)}
Tasa de Interés:       ${config.getDefaultInterestRate()}%
Plazo:                 ${appConfigService.getDefaultLoanTermDays()} días
Período de Gracia:     ${appConfigService.getGracePeriodDays()} días

─────────────────────────────────────────

Interés Calculado:     ${appConfigService.formatCurrency(
      BusinessConfigHelper.calculateSimpleInterest(
        amount: amount,
        days: appConfigService.getDefaultLoanTermDays(),
      )
    )}
Total a Pagar:         ${appConfigService.formatCurrency(
      BusinessConfigHelper.calculateTotalWithInterest(
        amount: amount,
        days: appConfigService.getDefaultLoanTermDays(),
      )
    )}

─────────────────────────────────────────

Teléfono: ${config.getPhone() ?? 'No disponible'}
Email:    ${config.getEmail() ?? 'No disponible'}

${config.shouldShowLogoOnReceipt() ? '┌───────────┐\n│   LOGO    │\n└───────────┘' : ''}

${config.getReceiptFooter()}

═════════════════════════════════════════
    ''';
  }

  /// Ejemplo 5: Verificar si se debe activar recordatorio
  static bool shouldActivateLoanReminder() {
    return appConfigService.areLoanRemindersEnabled();
  }

  /// Ejemplo 6: Aplicar configuración a módulo de ventas
  static void applySalesConfiguration() {
    double taxRate = appConfigService.getDefaultTaxRate();
    bool taxIncluded = appConfigService.isTaxIncludedInPrices();
    String currency = appConfigService.getCurrencySymbol();
    
    print('''
    CONFIGURACIÓN DE VENTAS
    ========================
    Tasa de Impuesto (ITBIS): $taxRate%
    Impuesto Incluido en Precios: $taxIncluded
    Símbolo de Moneda: $currency
    
    Ejemplo:
    - Precio Base: $currency 100.00
    - Impuesto: $currency ${BusinessConfigHelper.calculateTax(amount: 100)}
    - Total: $currency ${BusinessConfigHelper.calculateTotalWithTax(amount: 100)}
    ''');
  }

  /// Ejemplo 7: Obtener resumen completo de configuraciones
  static void printConfigurationSummary() {
    final summary = BusinessConfigHelper.getConfigurationSummary();
    
    print('''
    RESUMEN DE CONFIGURACIONES
    ============================
    ${summary.entries.map((e) => '${e.key}: ${e.value}').join('\n')}
    ''');
  }

  /// Ejemplo 8: Usar en cálculo de descuento con impuesto
  static double applyDiscountAndTax(double originalPrice, double discountPercent) {
    // Aplicar descuento
    final discountAmount = originalPrice * (discountPercent / 100);
    final priceAfterDiscount = originalPrice - discountAmount;
    
    // Aplicar impuesto
    final finalPrice = BusinessConfigHelper.calculateTotalWithTax(
      amount: priceAfterDiscount,
    );
    
    return finalPrice;
  }
}

/// Ejemplo de uso en un Provider de Riverpod
/// 
/// ```dart
/// final loanCalculatorProvider = StateNotifierProvider<LoanCalculator, LoanState>((ref) {
///   return LoanCalculator(ref);
/// });
/// 
/// class LoanCalculator extends StateNotifier<LoanState> {
///   final Ref ref;
///   
///   LoanCalculator(this.ref) : super(LoanState.initial());
///   
///   Future<void> createLoan(double amount) async {
///     // Obtener configuraciones automáticamente
///     final interestRate = appConfigService.getDefaultInterestRate();
///     final days = appConfigService.getDefaultLoanTermDays();
///     
///     final interest = BusinessConfigHelper.calculateSimpleInterest(
///       amount: amount,
///       days: days,
///     );
///     
///     // Crear modelo de préstamo
///     final loan = Loan(
///       amount: amount,
///       interest: interest,
///       interestRate: interestRate,
///       days: days,
///     );
///     
///     // Guardar en BD
///     await _repository.createLoan(loan);
///     
///     state = state.copyWith(loans: [...state.loans, loan]);
///   }
/// }
/// ```*/