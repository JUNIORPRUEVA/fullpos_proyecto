class Product {
  const Product({
    required this.id,
    this.localId,
    required this.code,
    required this.name,
    this.category,
    this.description,
    required this.price,
    required this.cost,
    required this.stock,
    this.imageUrl,
    this.isDemo = false,
    this.isActive = true,
    this.version = 0,
    this.lastModifiedBy,
    this.createdAt,
    this.updatedAt,
    this.deletedAt,
  });

  final int id;
  final int? localId;
  final String code;
  final String name;
  final String? category;
  final String? description;
  final double price;
  final double cost;
  final double stock;
  final String? imageUrl;
  final bool isDemo;
  final bool isActive;
  final int version;
  final String? lastModifiedBy;
  final DateTime? createdAt;
  final DateTime? updatedAt;
  final DateTime? deletedAt;

  factory Product.fromJson(Map<String, dynamic> json) => Product(
    id: json['id'] as int,
    localId: json['localId'] as int?,
    code: json['code'] as String,
    name: json['name'] as String,
    category: _readCategory(json),
    description: json['description'] as String?,
    price: (json['price'] as num).toDouble(),
    cost: (json['cost'] as num?)?.toDouble() ?? 0,
    stock: (json['stock'] as num).toDouble(),
    imageUrl: json['imageUrl'] as String?,
    isDemo: json['isDemo'] as bool? ?? false,
    isActive: json['isActive'] as bool? ?? true,
    version: json['version'] as int? ?? 0,
    lastModifiedBy: json['lastModifiedBy'] as String?,
    createdAt: json['createdAt'] != null
        ? DateTime.parse(json['createdAt'] as String)
        : null,
    updatedAt: json['updatedAt'] != null
        ? DateTime.parse(json['updatedAt'] as String)
        : null,
    deletedAt: json['deletedAt'] != null
        ? DateTime.parse(json['deletedAt'] as String)
        : null,
  );

  Product copyWith({
    int? id,
    int? localId,
    String? code,
    String? name,
    String? category,
    String? description,
    double? price,
    double? cost,
    double? stock,
    String? imageUrl,
    bool? isDemo,
    bool? isActive,
    int? version,
    String? lastModifiedBy,
    DateTime? createdAt,
    DateTime? updatedAt,
    DateTime? deletedAt,
  }) {
    return Product(
      id: id ?? this.id,
      localId: localId ?? this.localId,
      code: code ?? this.code,
      name: name ?? this.name,
      category: category ?? this.category,
      description: description ?? this.description,
      price: price ?? this.price,
      cost: cost ?? this.cost,
      stock: stock ?? this.stock,
      imageUrl: imageUrl ?? this.imageUrl,
      isDemo: isDemo ?? this.isDemo,
      isActive: isActive ?? this.isActive,
      version: version ?? this.version,
      lastModifiedBy: lastModifiedBy ?? this.lastModifiedBy,
      createdAt: createdAt ?? this.createdAt,
      updatedAt: updatedAt ?? this.updatedAt,
      deletedAt: deletedAt ?? this.deletedAt,
    );
  }
}

String? _readCategory(Map<String, dynamic> json) {
  final candidates = [
    json['category'],
    json['categoryName'],
    json['category_name'],
  ];

  for (final candidate in candidates) {
    if (candidate is String && candidate.trim().isNotEmpty) {
      return candidate.trim();
    }
    if (candidate is Map<String, dynamic>) {
      final name = candidate['name'];
      if (name is String && name.trim().isNotEmpty) {
        return name.trim();
      }
    }
  }

  return null;
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

  factory PaginatedProducts.fromJson(Map<String, dynamic> json) =>
      PaginatedProducts(
        data: (json['data'] as List)
            .map((item) => Product.fromJson(item as Map<String, dynamic>))
            .toList(),
        total: json['total'] as int? ?? 0,
        page: json['page'] as int? ?? 1,
        pageSize: json['pageSize'] as int? ?? 20,
      );
}
