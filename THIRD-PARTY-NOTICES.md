# Third-party notices

Lockbox takes no package dependencies. It includes one third-party file.

## BIP39 English wordlist

- **File:** `src/Lockbox.Core/Resources/bip39-english.txt`, embedded in `lockbox` and
  `lockbox-ui` for generated passphrases.
- **Source:** the English wordlist of BIP 39, "Mnemonic code for generating deterministic
  keys", by Marek Palatinus, Pavol Rusnak, Aaron Voisine and Sean Bowe:
  https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt. The same list, byte for
  byte apart from line endings, is in the reference implementation
  https://github.com/trezor/python-mnemonic (`src/mnemonic/wordlist/english.txt`).
- **License:** MIT. BIP 39 states `License: MIT` and "This BIP falls under the MIT License".
  The reference implementation's license, reproduced below, carries the copyright notice.

```text
The MIT License (MIT)

Copyright (c) 2013-2016 Pavol Rusnak

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
