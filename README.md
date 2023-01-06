### For Reproducing the issue

1. checkout this [commit](https://github.com/shekohex/webb-ark-circom-issue/commit/8781042568e40928f5211f755bd40cb9a450dc3c), then run the tests

```
git checkout 8781042568e40928f5211f755bd40cb9a450dc3c
```
```
cargo t -r
```

it will error with `Proof is not verified`.

2. Then, checkout this [commit](https://github.com/shekohex/webb-ark-circom-issue/commit/dd721e64c196a498acd8800e25b4ed0f341d62c6), you can see the [diff](https://github.com/shekohex/webb-ark-circom-issue/commit/dd721e64c196a498acd8800e25b4ed0f341d62c6?diff=split), then run the tests again
```
git checkout dd721e64c196a498acd8800e25b4ed0f341d62c6
```
```
cargo t -r
```

it will work as expected.
