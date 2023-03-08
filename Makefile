html: xml
	xml2rfc --html draft-aegis-mimi-arch-latest.xml

txt: xml
	xml2rfc draft-aegis-mimi-arch-latest.xml

xml: draft-aegis-mimi-arch-latest.md
	kramdown-rfc2629 draft-aegis-mimi-arch-latest.md > draft-aegis-mimi-arch-latest.xml

clean:
	$(call delete,draft-aegis-mimi-arch-latest.xml)
	$(call delete,draft-aegis-mimi-arch-latest.txt)
	$(call delete,draft-aegis-mimi-arch-latest.html)
	$(call delete,tracker.log)


define delete
	if [ -f $(1) ]; then rm $(1); fi
endef
