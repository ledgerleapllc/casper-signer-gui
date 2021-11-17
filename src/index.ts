import {
  QMainWindow, 
  QWidget, 
  QLabel, 
  FlexLayout, 
  QPushButton,
  QIcon,
  QLineEdit
} from '@nodegui/nodegui';

import logo from '../assets/favicon32x32.png';
import * as ed from 'noble-ed25519';
import * as asn from 'asn1-parser';
import * as crypto from 'crypto';

ed.utils.sha512 = async (message) => {
  return Uint8Array.from(crypto.createHash('sha512').update(message).digest());
}

exports.crypto;

const DEV_MODE = true;


// layout
const win = new QMainWindow();
win.setWindowTitle("Casper Node Signer");

const centralWidget = new QWidget();
centralWidget.setObjectName("app");

const rootLayout = new FlexLayout();
centralWidget.setLayout(rootLayout);

var is_secp256k1 = false;

const homedir = require('os').homedir();


// stylesheet
const fs = require('fs');
const stylesheet = fs.readFileSync(
  './assets/stylesheet.css', 
  {
    encoding:'utf8', 
    flag:'r'
  }
);


// functions
const verify = async(
  signature: string, 
  orig_msg: string, 
  public_key: string
) => {
  var verified = await ed.verify(
    signature, 
    orig_msg, 
    public_key
  );

  if(verified) {
    return true
  }

  return false;
}

const get_public_key = async(
  sk: string
) => {
  var pk = await ed.getPublicKey(sk);
  return pk;
}

const verify_public_key = (
  _k: string,
  length: number
) => {
  let size = _k.length;
  let firstbyte = _k.slice(0, 2);

  if(firstbyte == '01') {
    length = 66;
  } else if(firstbyte == '02') {
    length = 68;
  } else {
    return false;
  }

  if(
    size != length ||
    !(/^[0-9a-fA-F]+$/).test(_k)
  ) {
    return false;
  }

  return true;
}

const verify_secret_key = (
  _k: Uint8Array
) => {
  let size = _k.length;

  if(size != 32) {
    return false;
  }

  return true;
}

const pem_to_bytes = (
  c: string
) => {
  var der = asn.PEM.parseBlock(c).der;
  var obj = asn.ASN1.parse(der);
  var bytearr;

  if('children' in obj) {
    for(var ia = 0; ia < obj.children.length; ia++) {
      if('value' in obj.children[ia]) {
        if(obj.children[ia].value.length == 32) {
          bytearr = obj.children[ia].value;
          return bytearr;
        }
      }

      if('children' in obj.children[ia]) {
        for(var ib = 0; ib < obj.children[ia].children.length; ib++) {
          if('value' in obj.children[ia].children[ib]) {
            if(obj.children[ia].children[ib].value.length == 32) {
              bytearr = obj.children[ia].children[ib].value;
              return bytearr;
            }
          }

          if('children' in obj.children[ia].children[ib]) {
            for(var ic = 0; ic < obj.children[ia].children[ib].children.length; ic++) {
              if('value' in obj.children[ia].children[ib].children[ic]) {
                if(obj.children[ia].children[ib].children[ic].value.length == 32) {
                  bytearr = obj.children[ia].children[ib].children[ic].value;
                  return bytearr;
                }
              }
            }
          }
        }
      }
    }
  }

  return new Uint8Array(32);
}


// header
const label_header = new QLabel();
label_header.setObjectName("label-header");
label_header.setText("Casper Node Signer");

const label_subheader = new QLabel();
label_subheader.setObjectName("label-subheader");
label_subheader.setText("Use this form to generate a unique signature used to verify ownership of your node.");


// labels
const label_message = new QLabel();
label_message.setObjectName("label-message");
label_message.setText("Please specify your message file");

const label_public = new QLabel();
label_public.setObjectName("label-public");
label_public.setText("Please enter your validator ID (hex)");

const label_secret = new QLabel();
label_secret.setObjectName("label-secret");
label_secret.setText("Please specify the path to your secret key<br><small>(default: /etc/casper/validator_keys/secret_key.pem)</small>");


// inputs
const input_message = new QLineEdit();
input_message.setObjectName('input-message');
input_message.setPlaceholderText('Path to your downloaded message file');
input_message.setText('~/Downloads/message.txt');

const input_public = new QLineEdit();
input_public.setObjectName('input-public');
input_public.setPlaceholderText('Your validator ID');
if(DEV_MODE) input_public.setText('01bee8817a99d8a1cf23434c5b25a90dba00947d2d4a0a827aa1eca60da0ee22b8');

const input_secret = new QLineEdit();
input_secret.setObjectName('input-secret');
input_secret.setPlaceholderText('Path to your secret key file');
if(DEV_MODE) input_secret.setText(homedir+'/git/casper/caspersignerverifier/test/test.secret.key');
else input_secret.setText('/etc/casper/validator_keys/secret_key.pem');

// signature
const signature = new QLabel();
signature.setObjectName('signature');
signature.setText('');


// buttons
const button = new QPushButton();
button.setText('Create My Signature');
button.setObjectName('submit-btn');

button.addEventListener('clicked', async () => {
  var value_message = input_message.text();
  var content_public = input_public.text();
  var value_secret = input_secret.text();

  value_message = value_message.replace('~', homedir);
  value_secret = value_secret.replace('~', homedir);
  // is_secp256k1 = checkbox.isChecked();
  is_secp256k1 = false;

  var content_message = '';
  var content_secret = '';

  var length = 66;

  if(is_secp256k1) {
    length = 68;
  }

  try {
    content_message = fs.readFileSync(
      value_message,
      {
        encoding:'utf8', 
        flag:'r'
      }
    );
  } catch(err) {
    signature.setText('Cannot find message file: '+value_message);
    return false;
  }

  if(content_public == '') {
    signature.setText('Please enter your validator ID');
    return false;
  }

  if(!verify_public_key(content_public, length)) {
    return 'Invalid validator ID. Expecting a '+length+' character hexadecimal string';
  }

  try {
    content_secret = fs.readFileSync(
      value_secret,
      {
        encoding:'utf8', 
        flag:'r'
      }
    );
  } catch(err) {
    signature.setText('Cannot find secret key file: '+value_secret);
    return false;
  }

  var sig = null;
  var secret_bytes = pem_to_bytes(content_secret);

  try {
    sig = await ed.sign(
      content_message, 
      secret_bytes
    );
  } catch(err) {
    signature.setText('Invalid secret key');
    return false;
  }

  if(sig.length == 128) {
    fs.writeFileSync(
      homedir + '/a-signature.txt',
      sig
    );

    var public_key = await get_public_key(secret_bytes)
    var verified_text = '';
    var verified = await verify(
      sig, 
      content_message, 
      public_key
    );

    if(verified) {
      verified_text = '<br><small><span style="color:green;">Signature verified</span></small>';
    } else {
      verified_text = '<br><small><span style="color:red;">Signature not verified</span></small>';
    }

    signature.setText("Success! Your signature has been written to ~/signature.txt"+verified_text);
  } else {
    signature.setText('Invalid secret key');
  }
});


// inti
rootLayout.addWidget(label_header);
rootLayout.addWidget(label_subheader);
rootLayout.addWidget(label_message);
rootLayout.addWidget(input_message);
rootLayout.addWidget(label_public);
rootLayout.addWidget(input_public);
rootLayout.addWidget(label_secret);
rootLayout.addWidget(input_secret);
rootLayout.addWidget(button);
rootLayout.addWidget(signature);
win.setCentralWidget(centralWidget);
win.setStyleSheet(stylesheet);

win.show();

input_public.setFocus();

(global as any).win = win;
