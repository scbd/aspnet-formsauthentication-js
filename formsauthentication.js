var buffer = require('buffer');
var crypto = require('crypto');
var BufferReader = require('./lib/BufferReader');
var BufferWriter = require('./lib/BufferWriter');

function FormsAuthentication(options) {

	this.options = {
		validation: 'sha256',
		validationKey: null,
		validationHashLength: 256,
		encryption: 'aes-192-cbc',
		encryptionKey: null,
		encryptionBlockSize: 128,
		encryptionIv: new Buffer(16)
	};

	this.initialize(options);
}

//============================================================
//
//
//============================================================
FormsAuthentication.prototype.initialize = function(options) {

	if(options && options.validationKey) this.options.validationKey = new Buffer(options.validationKey, 'hex');
	if(options && options.encryptionKey) this.options.encryptionKey = new Buffer(options.encryptionKey, 'hex');

	this.options.encryptionIv.fill(0);
};

//============================================================
//
//
//============================================================
FormsAuthentication.prototype.encrypt = function(ticket) {

	// SERIALIZE

	var writer = new BufferWriter(crypto.randomBytes(24));

	writer.writeUInt8(1);
	writer.writeUInt8(ticket.version);
	writer.writeDate(ticket.issueDate);
	writer.writeUInt8(254);
	writer.writeDate(ticket.expiration);
	writer.writeBoolean(ticket.isPersistent);
	writer.writeString(ticket.name);
	writer.writeString(ticket.userData);
	writer.writeString(ticket.cookiePath);

	var decryptedTicket = writer.final();

	// ENCRYPT

	var cipher = crypto.createCipheriv(this.options.encryption, this.options.encryptionKey, this.options.encryptionIv);

	var buffer1 = cipher.update(decryptedTicket);
	var buffer2 = cipher.final();

	var encryptedTicketData = Buffer.concat([buffer1, buffer2]);

	// SIGN

	var hmac = crypto.createHmac(this.options.validation, this.options.validationKey);
	hmac.update(encryptedTicketData);
	var hash = hmac.digest();

	var encryptedTicket = Buffer.concat([encryptedTicketData, hash]);

	return encryptedTicket.toString('hex').toUpperCase();
};

//============================================================
// encryptedTicket : HEX string
//
//============================================================
FormsAuthentication.prototype.decrypt = function(encryptedTicket) {

	var data = new Buffer(encryptedTicket, 'hex');
	var encryptedTicketData = data.slice(0, data.length - this.options.validationHashLength / 8);
	var encryptedTicketSignature = data.slice(data.length - this.options.validationHashLength / 8);

	// CHECK SIGNATURE

	var hmac = crypto.createHmac(this.options.validation, this.options.validationKey);
	hmac.update(encryptedTicketData);
	var hash = hmac.digest();

	if(hash.toString()!=encryptedTicketSignature.toString())
		throw new Error('encryptedTicket is of an invalid format.');

	// DECRYPT

	var decipher = crypto.createDecipheriv(this.options.encryption, this.options.encryptionKey, this.options.encryptionIv);

	var buffer1 = decipher.update(encryptedTicketData);
	var buffer2 = decipher.final();

	var decryptedTicket = Buffer.concat([buffer1, buffer2]).slice(24);

	// DESERIALIZE

	var reader = new BufferReader(decryptedTicket);

	var ticket = {
		x: 	 		  reader.readUInt8(),	// 1
		version: 	  reader.readUInt8(),
		issueDate:    reader.readDate(),
		y: 	  		  reader.readUInt8(),	// 254
		expiration:	  reader.readDate(),
		isPersistent: reader.readUInt8(),
		name:         reader.readString(),
		userData:     reader.readString(),
		cookiePath:   reader.readString(),
	};

	return ticket;
};

exports = module.exports = new FormsAuthentication();

