
describe('FormsAuthentication', function() {

    describe('encrypt()', function () {

        var assert = require("assert");
        var auth = require('../formsauthentication.js');

        var ticket = {
            version:        1,
        	issueDate:      new Date('2015-09-29T19:31:18.959Z'),
        	expiration:     new Date('2015-09-29T19:32:31.232Z'),
        	isPersistent:   false,
        	name:           'MOCHA',
        	userData:       '12345678901234567890',
        	cookiePath:     '/'
        };

        auth.initialize({
            validationKey: '0372DACF9F7184F83965CE3FB60D8F561793A6AFA6F81141',  // 192-bit
            encryptionKey: '03AA620E7B77EBC3FEB1F58AF7C2435FC21202F7DE03BF6B',  // 192-bit
            ramdomBlockSize: 0                                                  // FOR TESTING
        });

        it('should match reference value', function () {
            assert.equal('DFE23949D62DC150AB4550372D7E18C5EE5F0FD9ADA161064B31D31E6324A412071595AD854C70C6E3790A7F0E05255E8A97C66D0DC6DBAF9DEF66F7D41AE13F3A02B8BFC61406968930BDDFB911C4A673E6BFDDDA187CCDB9624A0D902B93F753E267F3AA97E7F10BCA2E30FB6FB90B3AE4DA9F3DB26BBB41FAB3A26B24546DF8339A3988912D1860DD1DA58D09E077', auth.encrypt(ticket));
        });
    });

    describe('decrypt()', function () {

        var assert = require("assert");
        var auth = require('../formsauthentication.js');

        auth.initialize({
            validationKey: '0372DACF9F7184F83965CE3FB60D8F561793A6AFA6F81141',  // 192-bit
            encryptionKey: '03AA620E7B77EBC3FEB1F58AF7C2435FC21202F7DE03BF6B',  // 192-bit
            ramdomBlockSize: 0                                                  // FOR TESTING
        });

        it('should match reference value', function () {

            var ticket = auth.decrypt('DFE23949D62DC150AB4550372D7E18C5EE5F0FD9ADA161064B31D31E6324A412071595AD854C70C6E3790A7F0E05255E8A97C66D0DC6DBAF9DEF66F7D41AE13F3A02B8BFC61406968930BDDFB911C4A673E6BFDDDA187CCDB9624A0D902B93F753E267F3AA97E7F10BCA2E30FB6FB90B3AE4DA9F3DB26BBB41FAB3A26B24546DF8339A3988912D1860DD1DA58D09E077');

            assert.equal(ticket.version,      1);
            assert.equal(ticket.issueDate.toISOString(),  (new Date('2015-09-29T19:31:18.959Z')).toISOString());
            assert.equal(ticket.expiration.toISOString(), (new Date('2015-09-29T19:32:31.232Z')).toISOString());
            assert.equal(ticket.isPersistent, false);
            assert.equal(ticket.name,         'MOCHA');
            assert.equal(ticket.userData,     '12345678901234567890');
            assert.equal(ticket.cookiePath,   '/');
        });
    });
});
