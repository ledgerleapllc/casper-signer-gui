<p align="center">
	<img src="https://ledgerleap.com/web/images/casper-signer-gui.png" width="50">
</p>

## Casper Node Signer/Verifier GUI

A much more user friendly implementation of the old python3 signer. Used for providing signatures as proof of ownership to the Casper Association.

### Requirements

* Supports macOS 10.10
* CMake 3.1+
* Make, GCC v7
* NodeJs 14.x

### Setup

```bash
git clone https://github.com/ledgerleapllc/casper-signer-gui.git
cd casper-signer-gui/
npm install
npm start
```

### Usage

Once the GUI pops up, specify the path to your **message.txt** file that you downloaded from the Casper Association. Specify your public validator ID (hex string). Specify the path to your secret key PEM file. Click **Create My Signature**. If successful (keys and validator ID match), then the widget will output your signature file to your home DIR **~/signature.txt**. From there, simply upload the signature to the Casper Association portal.

<p align="center">
	<img src="https://ledgerleap.com/web/images/casper-signer-gui-sample.png" width="560">
</p>

### SECP256k1 Support

Now supported as of 11/18/2021. SECP256k1 validator IDs always begin with a **02** byte. The program will automatically detect this and interpret your keys and signature as being derived using this type curve.

### Resources for Learning NodeGui

- [docs.nodegui.org](https://nodegui.github.io/nodegui) - all of NodeGui and React Desktop's documentation

### Packaging app as a distributable

In order to distribute your finished app, you can use [@nodegui/packer](https://github.com/nodegui/packer)

## License

Apache2
