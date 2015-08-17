

int relic_cbor2ec_compressed(ec_t r, const cbor_stream_t *stream, size_t offset) {
	uint8_t value[FP_BYTES + 1];
	int ret = cbor_deserialize_byte_string(stream, offset, (char*)value, sizeof(value));
	ec_read_bin(r, value, FP_BYTES + 1);
	if (ec_is_valid(r) == 0) {
		printf("Decoded point is invalid.\n");
	}
	return ret;
}

int relic_cbor2bn(bn_t r, const cbor_stream_t *stream, size_t offset) {
	uint8_t value[32];
	int ret = cbor_deserialize_byte_string(stream, offset, (char*)value, sizeof(value));
	bn_read_bin(r, value, 32);
	return ret;
}

size_t relic_ec2cbor_compressed(cbor_stream_t *stream, const ec_t P) {
	uint8_t value[FP_BYTES + 1];
	ec_write_bin(value, sizeof(value), P, 1);
	return cbor_serialize_byte_stringl(stream, (char*)value, sizeof(value));
}

size_t relic_bn2cbor(cbor_stream_t *stream, bn_t n) {
	uint8_t value[32];
	bn_write_bin(value, sizeof(value), n);
	return cbor_serialize_byte_stringl(stream, (char*)value, sizeof(value));
}
