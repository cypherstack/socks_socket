import 'package:socks_socket/socks.dart';
import 'package:socks_socket/socks_socket.dart' as legacy;
import 'package:test/test.dart';

void main() {
  test('the collision-free entrypoint preserves legacy state values', () {
    expect(SocksSocketState.values, legacy.ConnectionState.values);
    const legacy.ConnectionState state = SocksSocketState.connected;
    expect(state, legacy.ConnectionState.connected);
  });
}
