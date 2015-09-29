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
		encryptionIv: new Buffer(16),
		ramdomBlockSize : 24
	};

	this.initialize(options);
}

function hash(data, options) {

	var hmac = crypto.createHmac(options.validation, options.validationKey);

	hmac.update(data);
	
	return hmac.digest();
}

//============================================================
//
//
//============================================================
FormsAuthentication.prototype.initialize = function(options) {

	if(options && options.validationKey) this.options.validationKey = new Buffer(options.validationKey, 'hex');
	if(options && options.encryptionKey) this.options.encryptionKey = new Buffer(options.encryptionKey, 'hex');

	if(this.options.encryptionKey && this.options.encryptionKey.length*8 == 128) this.options.encryption = "aes-128-cbc";
	if(this.options.encryptionKey && this.options.encryptionKey.length*8 == 192) this.options.encryption = "aes-192-cbc";
	if(this.options.encryptionKey && this.options.encryptionKey.length*8 == 256) this.options.encryption = "aes-256-cbc";
	if(this.options.encryptionKey)   this.options.ramdomBlockSize = this.options.encryptionKey.length;

	if(this.options.validationKey && this.options.validationKey.length*8 <= 160) this.options.validation = "SHA1 ";
	if(this.options.validationKey && this.options.validationKey.length*8  > 160) this.options.validation = "SHA256";
	if(this.options.validationKey && this.options.validationKey.length*8  > 256) this.options.validation = "SHA512";

	if(options && options.encryption) this.options.encryption = options.encryption;
	if(options && options.validation) this.options.validation = options.validation;
  
	if(this.options.validation=="SHA1")   this.options.validationHashLength = 160;
	if(this.options.validation=="SHA2")   this.options.validationHashLength = 256;
	if(this.options.validation=="SHA256") this.options.validationHashLength = 256;
	if(this.options.validation=="SHA512") this.options.validationHashLength = 512;

	if(options && options.validationHashLength) this.options.validation = options.validationHashLength;
	if(options && options.ramdomBlockSize!==undefined) this.options.ramdomBlockSize = options.ramdomBlockSize;

	this.options.encryptionIv.fill(0);
};

//============================================================
//
//
//============================================================
FormsAuthentication.prototype.encrypt = function(ticket) {

	// SERIALIZE

	var writer = new BufferWriter(new Buffer([]));

	writer.writeUInt8(1);
	writer.writeUInt8(ticket.version);
	writer.writeDate(ticket.issueDate);
	writer.writeUInt8(254);
	writer.writeDate(ticket.expiration);
	writer.writeBoolean(ticket.isPersistent);
	writer.writeString(ticket.name);
	writer.writeString(ticket.userData);
	writer.writeString(ticket.cookiePath);
	writer.writeUInt8(255);

	// SIGN RAW

	var decryptedTicketData = writer.final();
	var decryptedTicketHash = hash(decryptedTicketData, this.options)
	var decryptedTicket     = Buffer.concat([decryptedTicketData, decryptedTicketHash]);

	// ENCRYPT

	var cipher = crypto.createCipheriv(this.options.encryption, this.options.encryptionKey, this.options.encryptionIv);

	var iv      = crypto.randomBytes(this.options.ramdomBlockSize);
	var buffer1 = cipher.update(Buffer.concat([iv, decryptedTicket]));
	var buffer2 = cipher.final();

	// SIGN ENCRYPTED

	var encryptedTicketData = Buffer.concat([buffer1, buffer2]);
	var encryptedTicketHash = hash(encryptedTicketData, this.options);
	var encryptedTicket     = Buffer.concat([encryptedTicketData, encryptedTicketHash]);

	return encryptedTicket.toString('hex').toUpperCase();
};

//============================================================
// encryptedTicket : HEX string
//
//============================================================
FormsAuthentication.prototype.decrypt = function(encryptedTicket) {

	var data = new Buffer(encryptedTicket, 'hex');
	var encryptedTicketData = data.slice(0, data.length - this.options.validationHashLength / 8);
	var encryptedTicketHash = data.slice(   data.length - this.options.validationHashLength / 8);

	// CHECK ENCRYPTED SIGNATURE

	var computedHash = hash(encryptedTicketData, this.options);

	if(computedHash.toString('hex') != encryptedTicketHash.toString('hex'))
		throw new Error('encryptedTicket is of an invalid format.');

	// DECRYPT

	var decipher = crypto.createDecipheriv(this.options.encryption, this.options.encryptionKey, this.options.encryptionIv);

	var buffer1 = decipher.update(encryptedTicketData);
	var buffer2 = decipher.final();

	var decryptedTicket = Buffer.concat([buffer1, buffer2]).slice(this.options.ramdomBlockSize);

	var decryptedTicketData = decryptedTicket.slice(0, decryptedTicket.length - this.options.validationHashLength / 8);
	var decryptedTicketHash = decryptedTicket.slice(   decryptedTicket.length - this.options.validationHashLength / 8);

	// CHECK SIGNATURE 1

	var computedHash = hash(decryptedTicketData, this.options);

	if(computedHash.toString('hex') != decryptedTicketHash.toString('hex'))
		throw new Error('encryptedTicket is of an invalid format.');

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
		z:            reader.readUInt8(),	// 255
	};

	return ticket;
};

exports = module.exports = new FormsAuthentication();