
function BufferWriter (buffer) {
	this.buffer = buffer;
}

BufferWriter.prototype.final = function () {
	var buffer = this.buffer;
	this.buffer = undefined;
	return buffer;
}

BufferWriter.prototype.writeUInt8 = function(value) {
	var buf = new Buffer(1)
	buf.writeUInt8(value, 0);
	this.buffer = Buffer.concat([this.buffer, buf]);
}

BufferWriter.prototype.writeUInt32LE = function(value) {
	var buf = new Buffer(4)
	buf.writeUInt32LE(value, 0);
	this.buffer = Buffer.concat([this.buffer, buf]);
}

BufferWriter.prototype.writeUInt64LE = function(value) {
	this.writeUInt32LE(value % 4294967296);
	this.writeUInt32LE(Math.floor(value / 4294967296));
}

BufferWriter.prototype.writeString = function(value) {
	this.writeUInt8(value.length);
	this.buffer = Buffer.concat([this.buffer, new Buffer(value, 'ucs2')]);
}

BufferWriter.prototype.writeBoolean = function(value) {
	this.writeUInt8(value ? 1 : 0);
}

BufferWriter.prototype.writeDate = function(value) {
	this.writeUInt64LE(value.getTime() * 10000 + 621355968000000000);
}

exports = module.exports = BufferWriter;