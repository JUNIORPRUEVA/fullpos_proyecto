class Product {
  const Product({
    required this.id,
    required this.code,
    required this.name,
    this.description,
    required this.price,
    required this.stock,
    this.imageUrl,
    this.isDemo = false,
    this.createdAt,
  });

  final int id;
  final String code;
  final String name;
  final String? description;
  final double price;
  final double stock;
  final String? imageUrl;
  final bool isDemo;
  final DateTime? createdAt;

  factory Product.fromJson(Map<String, dynamic> json) => Product(
        id: json['id'] as int,
        code: json['code'] as String,
        name: json['name'] as String,
        description: json['description'] as String?,
        price: (json['price'] as num).toDouble(),
        stock: (json['stock'] as num).toDouble(),
        imageUrl: json['imageUrl'] as String?,
        isDemo: json['isDemo'] as bool? ?? false,
        createdAt: json['createdAt'] != null ? DateTime.parse(json['createdAt'] as String) : null,
      );
}

class PaginatedProducts {
  PaginatedProducts({
    required this.data,
    required this.total,
    required this.page,
    required this.pageSize,
  });

  final List<Product> data;
  final int total;
  final int page;
  final int pageSize;

  factory PaginatedProducts.fromJson(Map<String, dynamic> json) => PaginatedProducts(
        data: (json['data'] as List).map((item) => Product.fromJson(item as Map<String, dynamic>)).toList(),
        total: json['total'] as int? ?? 0,
        page: json['page'] as int? ?? 1,
        pageSize: json['pageSize'] as int? ?? 20,
      );
}
