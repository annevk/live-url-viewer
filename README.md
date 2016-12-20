## Setup

To generate a new version of `url.js`:

```
npm i whatwg-url; echo 'window.Url = require("whatwg-url").URL;' > temp.js; browserify temp.js -o url.js
rm temp.js
```

Note: liveview.html, liveview2.html, and liveview3.html are identical. We should probably create
some kind of build script to put the whole thing together rather than keep all resources in Git.
Patches welcome!

Fixing https://github.com/jsdom/whatwg-url/issues/61 can help make uri-validate.html functional
again and provide more detailed feedback in liveview too.

## Acknowledgments

* Sam Ruby
* Sebastian Mayr
