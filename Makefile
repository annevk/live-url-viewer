copy: liveview.html
	cp liveview.html liveview2.html
	cp liveview.html liveview3.html

build:
	npm i whatwg-url; echo 'window.Url = require("whatwg-url").URL;' > temp.js; browserify temp.js -o url.js
	rm temp.js
	make copy

deploy:
	scp *.css *.html *.js anne:quuz.org/url/
