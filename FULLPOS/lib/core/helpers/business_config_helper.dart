import 'dart:math';
import '../services/app_configuration_service.dart';

/// Clase auxiliar para cálculos y operaciones basadas en configuraciones
class BusinessConfigHelper {
  
  /// Calcular interés simple en un préstamo
  /// amount: monto del préstamo
  /// days: número de días
  /// customRate: tasa custom (usa la por defecto si es null)
  static double calculateSimpleInterest({
    required double amount,
    required int days,
    double? customRate,
  }) {
    final rate = customRate ?? appConfigService.getDefaultInterestRate();
    return amount * (rate / 100) * (days / 365);
  }

  /// Calcular mora por atraso
  /// originalAmount: monto original del préstamo
  /// daysOverdue: días de atraso
  /// customRate: tasa custom (usa la por defecto si es null)
  static double calculateLateFee({
    required double originalAmount,
    required int daysOverdue,
    double? customRate,
  }) {
    if (daysOverdue <= 0) return 0;
    
    final graceDays = appConfigService.getGracePeriodDays();
    final effectiveDaysOverdue = (daysOverdue - graceDays).clamp(0, daysOverdue);
    
    if (effectiveDaysOverdue <= 0) return 0;
    
    final rate = customRate ?? appConfigService.getDefaultLateFeeRate();
    return originalAmount * (rate / 100) * (effectiveDaysOverdue / 365);
  }

  /// Calcular total a pagar incluyendo interés
  /// amount: monto del préstamo
  /// days: número de días
  static double calculateTotalWithInterest({
    required double amount,
    required int days,
    double? customInterestRate,
  }) {
    final interest = calculateSimpleInterest(
      amount: amount,
      days: days,
      customRate: customInterestRate,
    );
    return amount + interest;
  }

  /// Calcular impuesto sobre un monto
  /// amount: monto base
  /// customRate: tasa custom (usa la por defecto si es null)
  static double calculateTax({
    required double amount,
    double? customRate,
  }) {
    final rate = customRate ?? appConfigService.getDefaultTaxRate();
    return amount * (rate / 100);
  }

  /// Calcular total con impuesto
  /// amount: monto base
  /// includeInAmount: si true, el impuesto ya está incluido en amount
  static double calculateTotalWithTax({
    required double amount,
    bool includeInAmount = false,
    double? customRate,
  }) {
    if (includeInAmount || appConfigService.isTaxIncludedInPrices()) {
      return amount;
    }
    
    final tax = calculateTax(amount: amount, customRate: customRate);
    return amount + tax;
  }

  /// Calcular precio base sin impuesto
  /// totalAmount: monto total (con impuesto)
  static double calculateBasePrice({
    required double totalAmount,
    double? customRate,
  }) {
    if (appConfigService.isTaxIncludedInPrices()) {
      final rate = customRate ?? appConfigService.getDefaultTaxRate();
      final factor = 1 + (rate / 100);
      return totalAmount / factor;
    }
    return totalAmount;
  }

  /// Formatear cantidad monetaria
  static String formatMoney(double amount) {
    return appConfigService.formatCurrency(amount);
  }

  /// Calcular cuota mensual aproximada para un préstamo
  /// amount: monto del préstamo
  /// monthsCount: número de meses
  static double calculateMonthlyPayment({
    required double amount,
    required int monthsCount,
    double? customRate,
  }) {
    if (monthsCount <= 0) return 0;
    
    final rate = (customRate ?? appConfigService.getDefaultInterestRate()) / 100 / 12;
    final monthlyRate = rate;
    
    if (monthlyRate == 0) {
      return amount / monthsCount;
    }
    
    // Fórmula de cuota con interés
    final numerator = amount * monthlyRate * pow(1 + monthlyRate, monthsCount).toDouble();
    final denominator = (pow(1 + monthlyRate, monthsCount) - 1).toDouble();
    
    return numerator / denominator;
  }

  /// Obtener información del negocio formateada para encabezados
  static String getBusinessHeaderInfo() {
    return appConfigService.getFormattedBusinessInfo();
  }

  /// Verificar si se debe mostrar logo en documento
  static bool shouldShowLogoInDocument() {
    return appConfigService.hasLogo() && appConfigService.shouldShowLogoOnReceipt();
  }

  /// Obtener plazo por defecto en texto legible
  static String getDefaultLoanTermText() {
    final days = appConfigService.getDefaultLoanTermDays();
    if (days == 30) return '1 mes';
    if (days == 60) return '2 meses';
    if (days == 90) return '3 meses';
    if (days < 30) return '$days días';
    
    final months = (days / 30).toStringAsFixed(1);
    return '$months meses';
  }

  /// Verificar si hay configuración de contacto
  static bool hasContactInfo() {
    return appConfigService.getPhone() != null ||
        appConfigService.getEmail() != null ||
        appConfigService.getAddress() != null;
  }

  /// Obtener contacto principal
  static String? getPrimaryContact() {
    final phone = appConfigService.getPhone();
    if (phone != null && phone.isNotEmpty) return phone;
    
    final companyPhone = appConfigService.getCompanyPhone();
    return companyPhone.isEmpty ? null : companyPhone;
  }

  /// Validar configuración mínima
  static bool hasMinimumConfiguration() {
    return appConfigService.getBusinessName() != 'FULLPOS' &&
        appConfigService.getBusinessName().isNotEmpty;
  }

  /// Obtener resumen de configuración
  static Map<String, dynamic> getConfigurationSummary() {
    return {
      'businessName': appConfigService.getBusinessName(),
      'hasLogo': appConfigService.hasLogo(),
      'interestRate': appConfigService.getDefaultInterestRate(),
      'lateFeeRate': appConfigService.getDefaultLateFeeRate(),
      'taxRate': appConfigService.getDefaultTaxRate(),
      'currency': appConfigService.getCurrencySymbol(),
      'backupEnabled': appConfigService.isAutoBackupEnabled(),
      'notificationsEnabled': appConfigService.areNotificationsEnabled(),
      'loanRemindersEnabled': appConfigService.areLoanRemindersEnabled(),
    };
  }
}
