
function BufferReader (buffer) {
	this.buffer = buffer;
	this.offset = 0;
}

BufferReader.prototype.readUInt8 = function() {
	return this.buffer.readUInt8(this.offset++);
}

BufferReader.prototype.readUInt32LE = function() {
	this.offset += 4;
	return this.buffer.readUInt32LE(this.offset-4);
}

BufferReader.prototype.readUInt64LE = function() {
	return this.readUInt32LE() + this.readUInt32LE() * 4294967296;
}

BufferReader.prototype.readString = function() {
	var length = this.readUInt8();
	this.offset += length << 1;
	return this.buffer.toString('ucs2', this.offset - (length << 1), this.offset);	// UCS2-LE
}

BufferReader.prototype.readBoolean = function() {
	return !!this.readUInt8();
}

BufferReader.prototype.readDate = function() {
	return new Date((this.readUInt64LE() - 621355968000000000) / 10000);
}

exports = module.exports = BufferReader;