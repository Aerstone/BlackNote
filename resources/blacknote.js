"use strict";
var blacknote = {
    materials: function() {
        this.message = null;
        this.key = null;
        this.nonce = null;
        this.ciphertext = null;
        this.error = null;
    },
    //TODO mats.error are wrong
    decodeNonce: function(nonce) {
        try {
            var n = nacl.util.decodeBase64(nonce);
            if (n.length != nacl.secretbox.nonceLength) {
                return 'Bad nonce length: must be ' + nacl.secretbox.nonceLength + ' bytes';
                return null;
            }
            return n;
        } catch (e) {
            return 'Failed to decode nonce from Base64';
            return null;
        };
    },
    decodeKey: function(key) {
        try {
            var k = nacl.util.decodeBase64(key);
            if (k.length != nacl.secretbox.keyLength) {
                return 'Bad key length: must be ' + nacl.secretbox.keyLength + ' bytes';
                return null;
            }
            return k;
        } catch (e) {
            mats.error = 'Failed to decode key from Base64';
            return null;
        }
    },
    encrypt: function(plaintext) {
        var mats = new blacknote.materials;
        mats.message = plaintext;
        if (!mats.message) {
            return null;
        }
        mats.key = nacl.util.encodeBase64(nacl.randomBytes(nacl.secretbox.keyLength));
        mats.nonce = nacl.util.encodeBase64(nacl.randomBytes(nacl.secretbox.nonceLength));
        mats.encrypt = function(e) {
            var p, n, m;
            //TODO error check
            //e.preventDefault();
            mats.error = '';
            if (!(n = blacknote.decodeNonce(mats.nonce))) return;
            if (!(p = blacknote.decodeKey(mats.key))) return;
            m = nacl.util.decodeUTF8(mats.message);
            mats.ciphertext = nacl.util.encodeBase64(nacl.secretbox(m, n, p));
        }.bind(mats);
        mats.encrypt(mats.plaintext);
        mats.message = null;
        return mats;
    },
    decrypt: function(ciphertext, tag) {
        var tags = tag.split(":");
        var mats = new blacknote.materials;
        mats.key = blacknote.rfc4648Decode(tags[0]);
        mats.nonce = blacknote.rfc4648Decode(tags[1]);
        mats.ciphertext = blacknote.rfc4648Decode(ciphertext);
        mats.decrypt = function(e) {
            var p, n, b, m;
            //TODO error check
            //e.preventDefault();
            mats.error = '';
            if (!(n = blacknote.decodeNonce(mats.nonce))) return;
            if (!(p = blacknote.decodeKey(mats.key))) return;
            try {
                b = nacl.util.decodeBase64(mats.ciphertext);
            } catch (ex) {
                mats.error('Cannot decode box');
                return;
            }
            m = nacl.secretbox.open(b, n, p);
            if (m === false) {
                mats.error = 'Failed to decrypt';
                mats.message = '';
                return;
            }
            try {
                mats.message = nacl.util.encodeUTF8(m);
            } catch (ex) {
                mats.error('Cannot decode decrypted message to string');
                return;
            }
        }.bind(mats);
        mats.decrypt(mats.ciphertext);
        return mats.message;
    },

    addClass: function(id, classname) {
        document.getElementById(id).className =
            document.getElementById(id).className + " " + classname;
    },
    removeClass: function(id, classname) {
        document.getElementById(id).className =
            document.getElementById(id).className
            .replace(new RegExp('(?:^|\\s)' + classname + '(?:\\s|$)'), ' ');
    },

    hideCleartext: function() {
        blacknote.addClass("pre-crypt", "hidden");
    },
    showCleartext: function() {
        blacknote.removeClass("pre-crypt", "hidden");
    },

    hideLink: function() {
        blacknote.addClass("post-crypt", "hidden");
    },
    showLink: function() {
        blacknote.removeClass("post-crypt", "hidden");
    },
    selectLink: function() {
        var range = document.createRange();
        var selection = window.getSelection();
        range.selectNodeContents(document.getElementById('link'));
        selection.removeAllRanges();
        selection.addRange(range);
    },

    hideDecrypted: function() {
        blacknote.addClass("secret", "hidden");
    },
    showDecrypted: function() {
        blacknote.removeClass("secret", "hidden");
    },

    hideError: function() {
        blacknote.addClass("error", "hidden");
    },
    showError: function() {
        blacknote.removeClass("error", "hidden");
    },

    genPaste: function(plaintext) {
        var a = blacknote.encrypt(plaintext);
        if (!a) {
            return
        }
        var req = new XMLHttpRequest();
        var tag = blacknote.rfc4648Encode(a.key) + ':' + blacknote.rfc4648Encode(a.nonce); //SECRET
        req.open('POST', window.location.pathname + 's/', true);
        req.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
        //encodes base64 to RFC4648 URL encoded
        req.send('ciphertext=' + blacknote.rfc4648Encode(a.ciphertext));
        req.onload = function() {
            //TODO link?
            var baseURL = window.location.origin + window.location.pathname;
            var link = baseURL + "s/" + req.response + "#" + tag;

            var html = "<p>" + link + "</p>";
            document.getElementById("link").innerHTML = html;

            html = "<a class='btn' href='" + link + "'>Direct Link</a>";
            document.getElementById("direct-link").innerHTML = html;

            blacknote.hideCleartext();
            blacknote.showLink();
            blacknote.selectLink();

            //console.log(req.response);
        };
    },
    retrievePaste: function() {
        var plain = blacknote.decrypt(document.getElementById("secret").value, location.hash.split('#')[1]);
        //TODO this probably needs more and validation, it's pretty half assed to be frank
        document.getElementById("secret").value = plain.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    },
    rfc4648Encode: function(b64txt) {
        return b64txt.replace(/\+/g, '-').replace(/\//g, '_')
    },
    rfc4648Decode: function(b64txt) {
        return b64txt.replace(/\-/g, '+').replace(/_/g, '/')
    }
}
