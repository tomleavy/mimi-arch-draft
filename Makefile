html: xml
	xml2rfc --html draft-aegis-mimi-arch-latest.xml

txt: xml
	xml2rfc draft-aegis-mimi-arch-latest.xml

xml: draft-aegis-mimi-arch-latest.md
	kramdown-rfc2629 draft-aegis-mimi-arch-latest.md > draft-aegis-mimi-arch-latest.xml

clean:
	rm draft-aegis-mimi-arch-latest.xml
	rm tracker.log
