# comptime

Zig's `comptime` is interesting. Basically, you can write code that runs at
compile time. I wanted to explore this idea except the target language is C.

### Usage

```console
$ comptime --help
Comptime function preprocessor for C

Usage: comptime [OPTIONS] <FILE>...

Arguments:
  <FILE>...  Files to preprocess

Options:
  -p, --prefix <PREFIX>  Set prefix [default: comptime_]
  -e, --expand           Expand without linking
  -l, --libs <LIBS>      Link library
  -h, --help             Print help
  -V, --version          Print version
```

### Build

#### Release

```sh
cargo build --release
```

#### Testing

```sh
cargo build && cargo test
```

### License

MIT License
