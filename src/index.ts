import {
  QMainWindow, 
  QWidget, 
  QLabel, 
  FlexLayout,
  QBoxLayout, 
  QPushButton,
  QIcon,
  QLineEdit,
  QFileDialog,
  QRadioButton
} from '@nodegui/nodegui';

import logo from '../assets/favicon.png';
import * as ed from 'noble-ed25519';
import * as secp from 'secp256k1';
import * as asn from 'asn1-parser';
import * as crypto from 'crypto';

ed.utils.sha512 = async (message) => {
  return Uint8Array.from(crypto.createHash('sha512').update(message).digest());
}

exports.crypto;

const DEV_MODE = false;
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


// helper functions
const string_to_bytearray = (
  s: string
) => {
  var b = Buffer.from(s);
  var ba = [];

  for(var i = 0; i < b.length; i++) {
    ba.push(b[i]);
  }

  return(new Uint8Array(ba))
}

const get_key_type = (
  pk: string
) => {
  let firstbyte = pk.slice(0, 2);

  if(firstbyte == '02') {
    return true;
  }

  return false;
}

const get_public_key_ed = async(
  sk: string
) => {
  var pk = await ed.getPublicKey(sk);
  return pk;
}

const get_public_key_secp = async(
  sk: string
) => {
  var pk = await secp.publicKeyCreate(sk);
  return pk;
}

const verify_public_key_ed = (
  pk: string
) => {
  let size = pk.length;
  let firstbyte = pk.slice(0, 2);

  if(firstbyte != '01') {
    return false;
  }

  if(
    size != 66 ||
    !(/^[0-9a-fA-F]+$/).test(pk)
  ) {
    return false;
  }

  return true;
}

const verify_public_key_secp = (
  pk: string
) => {
  let size = pk.length;
  let firstbyte = pk.slice(0, 2);

  if(firstbyte != '02') {
    return false;
  }

  if(
    size != 68 ||
    !(/^[0-9a-fA-F]+$/).test(pk)
  ) {
    return false;
  }

  return true;
}

const verify_secret_key = (
  sk: Uint8Array
) => {
  let size = sk.length;

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

const sleep = async(
  delay: number
) => {
  return new Promise(resolve =>
    setTimeout(resolve, delay)
  );
}


// initialize
const win = new QMainWindow();
win.setWindowTitle("Casper Node Signer");
const icon_widget = new QIcon("./assets/favicon.png");
win.setWindowIcon(icon_widget);


// header
const root_widget = new QWidget();
const root_layout = new FlexLayout();
root_layout.setFlexNode(root_widget.getFlexNode());
root_widget.setObjectName("app");
root_widget.setLayout(root_layout);

const label_header = new QLabel();
label_header.setObjectName("label-header");
label_header.setText("Casper Node Signer");
root_layout.addWidget(label_header);

const label_subheader = new QLabel();
label_subheader.setObjectName("label-subheader");
label_subheader.setText("Use this form to generate a unique signature used to verify ownership of your node.");
root_layout.addWidget(label_subheader);


// first row
const label_public = new QLabel();
label_public.setObjectName("label-public");
label_public.setText("Please enter your validator ID (hex)");
root_layout.addWidget(label_public);

const input_public = new QLineEdit();
input_public.setObjectName('input-public');
input_public.setPlaceholderText('Your validator ID');
if(DEV_MODE) input_public.setText('0202968fc8ad12fc23d4c0908580ba6be4a7d5c823d032a5f403e71daecc2d2ae607');
root_layout.addWidget(input_public);


// second row
const label_message = new QLabel();
label_message.setObjectName("label-message");
label_message.setText("Please specify your message file");
root_layout.addWidget(label_message);

const container_message = new QWidget();
const layout_message = new FlexLayout();
layout_message.setFlexNode(container_message.getFlexNode());
container_message.setObjectName("container_message");
container_message.setLayout(layout_message);
root_layout.addWidget(container_message, container_message.getFlexNode());

const input_message = new QLineEdit();
input_message.setObjectName('input-message');
input_message.setPlaceholderText('Path to your downloaded message file');
input_message.setText('~/Downloads/message.txt');
layout_message.addWidget(input_message);

const filemodal_message = new QFileDialog();
// filemodal_message.setFileMode(FileMode.AnyFile);
filemodal_message.setNameFilter('Text (*.txt)');

const filebtn_message = new QPushButton();
filebtn_message.setText('Browse');
filebtn_message.setObjectName('message-btn');

filebtn_message.addEventListener('clicked', () => {
  filemodal_message.exec();
  let selectedFiles = filemodal_message.selectedFiles();
  //console.log(selectedFiles);
  input_message.setText(selectedFiles[0]);
});

layout_message.addWidget(filebtn_message);


// third row
const label_secret = new QLabel();
label_secret.setObjectName("label-secret");
label_secret.setText("Please specify the path to your secret key<br><small>(default: /etc/casper/validator_keys/secret_key.pem)</small>");
root_layout.addWidget(label_secret);

const container_secret = new QWidget();
const layout_secret = new FlexLayout();
layout_secret.setFlexNode(container_secret.getFlexNode());
container_secret.setObjectName("container_secret");
container_secret.setLayout(layout_secret);
root_layout.addWidget(container_secret, container_secret.getFlexNode());

const input_secret = new QLineEdit();
input_secret.setObjectName('input-secret');
input_secret.setPlaceholderText('Path to your secret key file');
if(DEV_MODE) input_secret.setText(homedir+'/git/casper/caspersignerverifier/test/secp256k1.secret.key');
else input_secret.setText('/etc/casper/validator_keys/secret_key.pem');
layout_secret.addWidget(input_secret);

const filemodal_secret = new QFileDialog();
// filemodal_secret.setFileMode(FileMode.AnyFile);
filemodal_secret.setNameFilter('Pem key (*.pem, *.key)');

const filebtn_secret = new QPushButton();
filebtn_secret.setText('Browse');
filebtn_secret.setObjectName('message-btn');

filebtn_secret.addEventListener('clicked', () => {
  filemodal_secret.exec();
  let selectedFiles = filemodal_secret.selectedFiles();
  //console.log(selectedFiles);
  input_secret.setText(selectedFiles[0]);
});

layout_secret.addWidget(filebtn_secret);


// submit button
const submit_button = new QPushButton();
submit_button.setText('Create My Signature');
submit_button.setObjectName('submit-btn');

submit_button.addEventListener('clicked', async () => {
  var value_message = input_message.text();
  var content_public = input_public.text();
  var value_secret = input_secret.text();
  var is_secp256k1 = get_key_type(content_public);

  value_message = value_message.replace('~', homedir);
  value_secret = value_secret.replace('~', homedir);

  var hashed_msg = new Uint8Array();
  var content_message = '';
  var content_secret = '';

  var sig = null;
  var verified = false;
  var verified_text = '';

  signature.setText('');
  await sleep(100);


  // handle public key
  if(content_public == '') {
    signature.setText('Please enter your validator ID');
    return false;
  }

  if(is_secp256k1) {
    if(!verify_public_key_secp(content_public)) {
      signature.setText('Invalid validator ID. Expecting a 68 character hex string');
      return false;
    }

    hashed_msg = Uint8Array.from(
      crypto.createHash('sha256')
        .update(string_to_bytearray(content_message))
        .digest()
    );
  } else {
    if(!verify_public_key_ed(content_public)) {
      signature.setText('Invalid validator ID. Expecting a 66 character hex string');
      return false;
    }
  }


  // handle message
  try {
    content_message = fs.readFileSync(
      value_message,
      {
        encoding:'utf8', 
        flag:'r'
      }
    );

    content_message = content_message.trim();
  } catch(err) {
    signature.setText('Cannot find message file: '+value_message);
    return false;
  }


  // handle secret key
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

  var secret_bytes = pem_to_bytes(content_secret);


  // handle signature
  if(is_secp256k1) {
    try {
      sig = secp.ecdsaSign(
        hashed_msg,
        secret_bytes
      );
      sig = sig.signature;
    } catch(err) {
      // console.log(err);
      signature.setText('Invalid secret key');
      return false;
    }
  } else {
    try {
      sig = await ed.sign(
        content_message, 
        secret_bytes
      );
    } catch(err) {
      // console.log(err);
      signature.setText('Invalid secret key');
      return false;
    }
  }


  // check signature
  if(is_secp256k1) {
    if(sig.length == 64) {
      fs.writeFileSync(
        homedir + '/signature.txt',
        Buffer.from(sig).toString('hex')
      );

      // match public key
      let derived_public_key = await get_public_key_secp(secret_bytes);
      let user_public_key = content_public.slice(2).toLowerCase();

      if(DEV_MODE) {
        console.log('derived_public_key: '+Buffer.from(derived_public_key).toString('hex'));
        console.log('user_public_key:    '+user_public_key);
      }

      if(Buffer.from(derived_public_key).toString('hex') !== user_public_key) {
        signature.setText('Validator ID does not match the one derived from your secret key');
        return false;
      }

      try {
        verified = await secp.ecdsaVerify(
          sig, 
          hashed_msg, 
          derived_public_key
        );
      } catch(err) {
        // console.log(err);
        verified = false;
      }

    } else {
      signature.setText('Invalid secret key');
      verified = false;
      return false;
    }
  } else {
    if(sig.length == 128) {
      fs.writeFileSync(
        homedir + '/signature.txt',
        sig
      );

      // match public key
      let derived_public_key = await get_public_key_ed(secret_bytes);
      derived_public_key = Buffer.from(derived_public_key).toString('hex');
      let user_public_key = content_public.slice(2).toLowerCase();

      if(DEV_MODE) {
        console.log('derived_public_key: '+derived_public_key);
        console.log('user_public_key:    '+user_public_key);
      }

      if(derived_public_key !== user_public_key) {
        signature.setText('Validator ID does not match the one derived from your secret key');
        return false;
      }

      try {
        verified = await ed.verify(
          sig, 
          content_message, 
          derived_public_key
        );
      } catch(err) {
        // console.log(err);
        verified = false;
      }

    } else {
      signature.setText('Invalid secret key');
      verified = false;
      return false;
    }
  }

  if(verified) {
    verified_text = '<br><small><span style="color:green;">Signature verified</span></small>';
  } else {
    verified_text = '<br><small><span style="color:red;">Signature not verified</span></small>';
  }

  signature.setText("Success! Your signature has been written to ~/signature.txt"+verified_text);
});

root_layout.addWidget(submit_button);


// signature message field
const signature = new QLabel();
signature.setObjectName('signature');
signature.setText('');
root_layout.addWidget(signature);


// show window
win.setCentralWidget(root_widget);
win.setStyleSheet(stylesheet);
win.setFixedSize(720, 560);
win.show();

input_public.setFocus();

(global as any).win = win;
