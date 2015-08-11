

int relic_cbor2ec_compressed(ec_t r, const cbor_stream_t *stream, size_t offset) {
	uint8_t value[33];
	int ret = cbor_deserialize_byte_string(stream, offset, (char*)value, sizeof(value));
	ec_read_bin(r, value, 33);
	return ret;
}

int relic_cbor2bn(bn_t r, const cbor_stream_t *stream, size_t offset) {
	uint8_t value[32];
	int ret = cbor_deserialize_byte_string(stream, offset, (char*)value, sizeof(value));
	bn_read_bin(r, value, 32);
	return ret;
}