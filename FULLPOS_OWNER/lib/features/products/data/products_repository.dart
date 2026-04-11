import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../../core/network/api_client.dart';
import 'product_models.dart';

final productsRepositoryProvider = Provider<ProductsRepository>((ref) {
  final dio = ref.read(apiClientProvider).dio;
  return ProductsRepository(dio);
});

class ProductsRepository {
  ProductsRepository(this._dio);
  final Dio _dio;

  Future<PaginatedProducts> list({int page = 1, int pageSize = 50, String? search}) async {
    final res = await _dio.get('/api/products', queryParameters: {
      'page': page,
      'pageSize': pageSize,
      if (search != null && search.isNotEmpty) 'search': search,
    });
    return PaginatedProducts.fromJson(res.data as Map<String, dynamic>);
  }

  Future<Product> getById(int id) async {
    final res = await _dio.get('/api/products/$id');
    return Product.fromJson(res.data as Map<String, dynamic>);
  }
}
