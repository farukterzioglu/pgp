	//Load the keys to textareas from the text files, containing PGP keys as text.
var filename, as_base64, as_binary;
var openFile = function(event, id, as_base64) {
	var input = event.target;
		var reader = new FileReader();
		reader.onload = function(){
			var text = reader.result;
			if(text.indexOf(String.fromCharCode(65533))!==-1){
				as_base64='as_base64';
				openFile(event, id, as_base64);
				document.getElementById(id).setAttribute('readonly', true);
				document.getElementById(id).setAttribute('title',
					'Unsigned character was been found in the source code.\n'+
					'Now this content was been uploaded as base64.\n'+
					'You can decode original source of this - from base64.\n\n'+
					'Double-click here to discard readonly attribute.'
				);
			}
			var node = document.getElementById(id);
			if(as_base64==='as_base64'){
				node.value = text.split(';base64,')[1];
			}
			else{
				node.value = text;
			}//console.log(reader.result.substring(0, 200));
		};
		
		if(input.files[0]===undefined){
			document.getElementById('filename_temp').innerHTML = '';
		}
		else{
			//set file name as temporary text in invisible div
			document.getElementById('filename_temp').innerHTML = input.files[0].name;
		}
		
		if(as_base64==='as_base64'){
			reader.readAsDataURL(input.files[0]);
			document.getElementById("filename_temp").innerHTML +='.base64'
		}else{
			reader.readAsText(input.files[0]);
		}
};

function isBase64(str) {
    try {
        return btoa(atob(str)) == str;
    } catch (err) {
        return false;
    }
}

function set_file_name(link, action, as_binary){
		
}
	  
//funtion to show and hide download link (button) for empty or filled readonly textarea's
function linkText(input, link, action, as_binary) { //IDs and filename
  link.style.display = 'none' ? 'block': 'block';
  updateLink(input, link);

	var filename = document.getElementById("filename_temp");
	if(filename===null){console.log('no element with ID '+filename_temp);}
	else{
		filename_temp = filename.innerHTML;
	}
	if(link===null){console.log('no element with ID '+link);}
	
	if(as_binary===undefined){
		if(isBase64(input.value)){
			if(filename_temp.indexOf('.base64')==-1){
				filename_temp = filename_temp+'.base64';
			}
		}
	}
	else{
		if(isBase64(input.value) && filename_temp.indexOf('.base64')!=-1){
			filename_temp = filename_temp.replace('.base64','');
		}
	}

  function onInput(as_binary, action) {
    updateLink(input, link, as_binary, action);
  }
  
  input.addEventListener("input", onInput(as_binary, action));
  return onInput;
}

//function to generate download links for buttons.
function updateLink(input, link, as_binary, action) { //
  link.hidden = !input.value;
	if(as_binary==='as_binary'){
		link.href = "data:application/octet-stream;base64," + encodeURI(input.value); //<-- base64 as binary
	}
	else{
		link.href = "data:text/plain;charset=UTF-8," + encodeURI(input.value); //<-- data in href
	}
  link.onclick = '';
  link.style.display = (input.value==='') ? 'none' : 'block';
  
	if(action==='sign'){
		var suffix = 'signed';
		link.download = (filename_temp==='') ? "text"+'.'+suffix+'.txt' : filename_temp+'.'+suffix+'.txt';
	}else if(action==='verify'){
		var suffix = 'verified'
		link.download = (filename_temp.indexOf('.signed.txt')!==1) ? filename_temp.replace('.signed.txt',''): "pure_text"+'.txt';
	}else if(action==='encrypt'){
		var suffix = 'encryted';
		link.download = (filename_temp==='') ? "text"+'.encrypted.txt' : filename_temp+'.encrypted.txt';
	}else if(action==='decrypt'){
		var suffix = 'decrypted';
		link.download = (filename_temp.indexOf('.encrypted.txt')!==1) ? filename_temp.replace('.encrypted.txt',''):"pure_text"+'.txt';
	}else if(action==='sign+encrypt'){
		var suffix = 'signed and encrypted';
		link.download = (filename_temp==='') ? "text"+'.encrypted_and_signed.txt' : filename_temp+'.encrypted_and_signed.txt';
	}else if(action==='decrypt+verify'){
		var suffix = 'decrypted and verified';
		link.download = (filename_temp.indexOf('.encrypted_and_signed.txt')!==1) ? filename_temp.replace('.encrypted_and_signed.txt','') : "pure_text"+'.txt';
	}
	
	if(as_binary===undefined){
		link.setAttribute('title', 'Download '+suffix+' message as text');
	}else{
		link.setAttribute('title', 'Download '+suffix+' message as binary.\n'+
		'If in textarea base64 encoded file content - you can download this as binary RAW-data.'
		);
	}
}


$(document).ready(function() {
    /* Dynamic key size menus */
    $('#algorithm').change(function() {
        populateKeysizeDropdown();
        $('#bitlength').removeAttr('disabled');
    });

    /* Set event handlers */
    $('form#keygen').submit(function(e) {
        e.preventDefault();
        genKeyPair();
    });

    $('#download_priv_key').on('click', downloadPrivKey);
    $('#download_pub_key').on('click', downloadPubKey);

    $('#name, #email, #comments, #algorithm, #bitlength, #expire, #passphrase').tooltip({
        trigger: 'hover',
        placement: 'top'
    });

    $('[data-toggle="popover"]').popover({placement: 'top'});
	
	//discard readonly attribute by double-click on textarea
	//readonly attribute using for protect base64 encoded binary data from any changes.
	$( "#sign-plain-text" ).dblclick(function() {
		$(this).removeAttr("title");
		$(this).removeAttr("readonly");
	});
	
	$( "#Unverified-plain-text" ).dblclick(function() {
		$(this).removeAttr("title");
		$(this).removeAttr("readonly");
	});
	
	$( "#signencrypt-plain-text" ).dblclick(function() {
		$(this).removeAttr("title");
		$(this).removeAttr("readonly");
	});
	
	$( "#decryption-encrypted-text" ).dblclick(function() {
		$(this).removeAttr("title");
		$(this).removeAttr("readonly");
	});
	
	
	

    // SIGN
    var signButton = $("#sign-button");

    signButton.click(function(){
        var signPlainText = $("#sign-plain-text");
        var SignedText = $("#signed-text");
        var signPrivateKey = $("#sign-private-key");
        var signPassphrase = $("#sign-passphrase");
		
		$('#vrAlert_signed').empty();
		var clone = $('#vrError').clone();
		
        var currUser = kbpgp.KeyManager.import_from_armored_pgp({
          armored: signPrivateKey.val()
        }, function(err, currUser) {
          if (!err) {
            if (currUser.is_pgp_locked()) {
              currUser.unlock_pgp({
                passphrase: signPassphrase.val()
              }, function(err) {
                if (!err) {
                  console.log("Loaded private key with passphrase");

                  var params = {
                    msg: signPlainText.val(),
                    sign_with: currUser
                  };

                  kbpgp.box(params, function(err, result_string, result_buffer) {
                    console.log(err, result_string, result_buffer);
                    SignedText.val(result_string);
					linkText(document.getElementById('signed-text'), document.getElementById('download-signed-text'), 'sign');
                  });
					
					clone = $('#vrSuccess').clone();
					clone.find('#vrAddrLabel').html("Message successfully signed.");
					clone.appendTo($('#vrAlert_signed'));
                }else{
					console.log("Error"+err);
					clone.find('#vrAddrLabel').html(err);
					clone.appendTo($('#vrAlert_signed'));
				}
              });
            } else {
              console.log("Loaded private key w/o passphrase");
			  clone.find('#vrAddrLabel').html("Invalid private key or password.");
			  clone.appendTo($('#vrAlert_signed'));
            }
          }
        });
  });
  //end Sign

  // Verify signature
    var VerifyButton = $("#verify-signature");

    VerifyButton.click(function(){
        var UnverifiedPlainText = $("#Unverified-plain-text");
        var PureText = $("#pure-text");
        var SignerPublicKey = $("#Signer-public-key");
		
		$('#vrAlert').empty();
		var clone = $('#vrError').clone();
		
        // import receiver's public key
        var receiver = kbpgp.KeyManager.import_from_armored_pgp({
          armored: SignerPublicKey.val()
        }, function(err, receiver) {
          if (!err) {
            console.log("receiver's public key is loaded");
			
            // encrypt the message
            var params = {
              msg: UnverifiedPlainText.val(),
              encrypt_for: receiver
            };
                  var ring = new kbpgp.keyring.KeyRing;
                  ring.add_key_manager(receiver);
				  
				  kbpgp.unbox({keyfetch: ring, armored: UnverifiedPlainText.val()}, function(err, literals) {
                    if (err != null) {
						//here is error if message was been encrypted by RSA public key,
						//but signed by ECC private key.
						clone.find('#vrAddrLabel').html("Message failed to verify! "+err);
                      return console.log("Problem: " + err);
                    } else {
                      var text = literals[0].toString();
                      console.log("decrypted message: " + text);

                      PureText.val(text);
					  linkText(document.getElementById('pure-text'), document.getElementById('download-pure-text'), 'verify');
					  linkText(document.getElementById('pure-text'), document.getElementById('download_verified_as_binary'), 'verify', 'as_binary');

                      var ds = km = null;
                      ds = literals[0].get_data_signer();
                      if (ds) { km = ds.get_key_manager(); }
                      if (km) {
                        console.log("Signed by PGP fingerprint");
                        var pub_f = receiver.get_pgp_fingerprint().toString('hex');
						var text_f = km.get_pgp_fingerprint().toString('hex');
						console.log(text_f, (pub_f===text_f) ? 'and verified.' : 'and failed to verify.');
						//console.log('fingerprint of public key from private:\n'+pub_f);

						//-> switch alert message
						clone = (pub_f === text_f) ? $('#vrSuccess').clone() : $('#vrWarning').clone();
						clone.find('#vrAddrLabel').html("Message signature is verified with fingerprint "+pub_f);
                      }
						clone.appendTo($('#vrAlert')); //display alert message
                    }
                  });

          } else {
            console.log("Error!");
			clone.find('#vrAddrLabel').html("Message failed to verify!");
			clone.appendTo($('#vrAlert'));
          }
        });
    });
	//end Verify signature

	// SIGN+Encrypt
  var signencryptButton = $("#signencrypt-button");

  signencryptButton.click(function() {
      var signencryptPlainText = $("#signencrypt-plain-text");
      var signencryptText = $("#signencrypt-text");
      var signencryptPrivateKey = $("#signencrypt-private-key");
      var signencryptPassphrase = $("#signencrypt-passphrase");
      var signencryptReceiversPublicKey = $("#signencrypt-receivers-public-key");

      $('#vrAlert3').empty();
      var clone = $('#vrError').clone();

      var currUser = kbpgp.KeyManager.import_from_armored_pgp({
          armored: signencryptPrivateKey.val()
      }, function(err, currUser) {
          if (!err) {
              if (currUser.is_pgp_locked()) {
                  currUser.unlock_pgp({
                      passphrase: signencryptPassphrase.val()
                  }, function(err) {
                      if (!err) {
                          console.log("Loaded private key with passphrase");
                      }
                      else{
						clone = $('#vrError').clone();
						clone.find('#vrAddrLabel').html("Signing error: Incorrect password for private key.");
						clone.appendTo($('#vrAlert3'));
                      }
                  });
              }
          }
          // import receiver's public key
          var receiver = kbpgp.KeyManager.import_from_armored_pgp({
              armored: signencryptReceiversPublicKey.val()
          }, function(err, receiver) {
              if (!err) {
                  console.log("receiver's public key is loaded");
                  console.log(receiver);

                  var params = {
                      msg: signencryptPlainText.val(),
                      sign_with: currUser,
                      encrypt_for: receiver
                  };

                  kbpgp.box(params, function(err, result_string, result_buffer) {
                      console.log(err, result_string, result_buffer);
                      signencryptText.val(result_string);
					    if(currUser===null){
							linkText(document.getElementById('signencrypt-text'), document.getElementById('download-signencrypt-text'), 'encrypt');
							clone = $('#vrWarning').clone();
							clone.find('#vrAddrLabel').html("Message successfully encrypted, but not signed. Private key not loaded.");
						}else{
							linkText(document.getElementById('signencrypt-text'), document.getElementById('download-signencrypt-text'), 'sign+encrypt');
							clone = $('#vrSuccess').clone();
							clone.find('#vrAddrLabel').html("Message successfully encrypted and signed.");
						}
						clone.appendTo($('#vrAlert3'));
                  });
              } else {
					console.log("Error!");
					clone = $('#vrError').clone();
					clone.find('#vrAddrLabel').html("Encryption error. Incorrect public key.");
					clone.appendTo($('#vrAlert3'));
			  }
          });
      });
  });
	//end SIGN+ENCRYPT

    // DECRYPTION(+VERIFY)
    var decryptionButton = $("#decryption-button");

    decryptionButton.click(function(){
        var decryptionEncryptedText = $("#decryption-encrypted-text");
        var decryptionDecryptedText = $("#decryption-decrypted-text");
        var decryptionPrivateKey = $("#decryption-private-key");
        var decryptionPassphrase = $("#decryption-passphrase");
        var PubSigVerify = $("#signer_public_key");

        
		//console.log(decryptionEncryptedText);

        $('#vrAlert2').empty();
		var clone = $('#vrError').clone();
		
		// import receiver's public key
        var currUser = kbpgp.KeyManager.import_from_armored_pgp({
          armored: decryptionPrivateKey.val()
        }, function(err, currUser) {
          if (!err) {
            if (currUser.is_pgp_locked()) {
              currUser.unlock_pgp({
                passphrase: decryptionPassphrase.val()
              }, function(err) {
                if (!err) {
                  console.log("Loaded private key with passphrase");

                  // add KeyRing
                  var ring = new kbpgp.keyring.KeyRing;
                  ring.add_key_manager(currUser);
					var senderPUB = kbpgp.KeyManager.import_from_armored_pgp
					(
						{armored: PubSigVerify.val()},
						function(err, senderPUB)
						{
							if (!err) {
								console.log("Sender's public key is loaded");
								ring.add_key_manager(senderPUB);
								
								kbpgp.unbox({keyfetch: ring, armored: decryptionEncryptedText.val()}, function(err, literals)
								{
									if (err != null) {
										clone.find('#vrAddrLabel').html("Message failed to verify! <br>"+ err);
										clone.appendTo($('#vrAlert2'));
										console.log(err);
									} else
									{
										var decryptedText = literals[0].toString();
										console.log("decrypted message: " + decryptedText);

										decryptionDecryptedText.val(decryptedText);
										
										linkText(
											document.getElementById('decryption-decrypted-text'),
											document.getElementById('download-decrypted-text'),
											'decrypt+verify'
										);
										linkText(
											document.getElementById('decryption-decrypted-text'),
											document.getElementById('download_decrypt_verify_as_binary'),
											'decrypt+verify', 'as_binary'
										);
										
										var ds = km = null;
										ds = literals[0].get_data_signer();
										if (ds) { km = ds.get_key_manager(); }
										if (km) {
											console.log("Signed by PGP fingerprint");
											var pub_f = senderPUB.get_pgp_fingerprint().toString('hex');
											var text_f = km.get_pgp_fingerprint().toString('hex');
											console.log(text_f, (pub_f===text_f) ? 'and verified.' : 'and failed to verify.');

											//-> switch alert message
											if(pub_f === text_f){
												clone = $('#vrSuccess').clone();
												clone.find('#vrAddrLabel').html("Message is decrypted by priv, and signature is verified successfully by pub - with fingerprint "+pub_f);
											}
											else{
												clone = $('#vrWarning').clone();
												clone.find('#vrAddrLabel').html("Incorrect fingerprint "+pub_f);
											}
						
										}else{
											clone = $('#vrWarning').clone();
											clone.find('#vrAddrLabel').html('Decrypted, but incorrect fingerprint - signature not verified.<br>If this message encrypted without signature - ignore this message.');
										}
										clone.appendTo($('#vrAlert2')); //display alert message
									}
								});
							}
							else{
								kbpgp.unbox({keyfetch: ring, armored: decryptionEncryptedText.val()}, function(err, literals)
								{
									if (err != null) {
										clone.find('#vrAddrLabel').html("Message failed to verify! <br>"+ err);
										clone.appendTo($('#vrAlert2'));
										console.log(err);
									} else
									{
										var decryptedText = literals[0].toString();
										console.log("decrypted message: " + decryptedText);

										decryptionDecryptedText.val(decryptedText);
										
										linkText(
											document.getElementById('decryption-decrypted-text'),
											document.getElementById('download-decrypted-text'),
											'decrypt'
										);
										linkText(
											document.getElementById('decryption-decrypted-text'),
											document.getElementById('download_decrypt_verify_as_binary'),
											'decrypt', 'as_binary'
										);
										
										var ds = km = null;
										ds = literals[0].get_data_signer();
										if (ds) { km = ds.get_key_manager(); }
										if (km) {
											console.log("Signed by PGP fingerprint");
											var pub_f = senderPUB.get_pgp_fingerprint().toString('hex');
											var text_f = km.get_pgp_fingerprint().toString('hex');
											console.log(text_f, (pub_f===text_f) ? 'and verified.' : 'and failed to verify.');
											
											//-> switch alert message
											if(pub_f === text_f){
												clone = $('#vrSuccess').clone();
												clone.find('#vrAddrLabel').html("Message is decrypted by priv, and signature is verified successfully by pub - with fingerprint "+pub_f);
											}
											else{
												clone = $('#vrWarning').clone();
												clone.find('#vrAddrLabel').html("Incorrect fingerprint "+pub_f);
											}
						
										}else{
											clone = $('#vrWarning').clone();
											clone.find('#vrAddrLabel').html('Decrypted, but incorrect fingerprint - signature not verified.<br>If this message encrypted without signature - ignore this message.');
										}
										clone.appendTo($('#vrAlert2')); //display alert message
									}
								});
							}
						}
					);
                } else {
                  console.log("Error in decryption unlock pgp");
				  clone = $('#vrWarning').clone();
				  clone.find('#vrAddrLabel').html('Incorrect password for private key');
				  clone.appendTo($('#vrAlert2'));
                }
              });
            } else {
              console.log("Loaded private key w/o passphrase");
			  clone.find('#vrAddrLabel').html("Invalid private key or password.");
			  clone.appendTo($('#vrAlert2'));
            }
          } else {
            console.log("Error in decryption import");
			clone.find('#vrAddrLabel').html("Error in decryption import");
			clone.appendTo($('#vrAlert2'));
          }

        });
    });
	//END Decryption(+Verify)
});
