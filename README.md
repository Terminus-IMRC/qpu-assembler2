# qpu-assembler2

Yet another assembler for VideoCore IV QPU.


## Requirements

You need to install `flex` (`lex` command) to compile qpu-assembler2.
On Debian dists, do:

```
$ sudo apt-get install flex
```


## Building

```
$ make
```

You can build Debian package by doing:

```
$ debuild -us -uc
```


## Usage

Use [qbin2hex](https://github.com/Terminus-IMRC/qpu-bin-to-hex) to convert the output to C/C++'s array style.

```
$ qasm2 <in.qasm2 | qbin2hex
```


## License

This software is licensed under a Modified (3-Clause) BSD License.
See the [LICENSE](LICENSE) file.
