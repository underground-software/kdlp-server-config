#!/bin/bash

KDLP_ROOT=/var/www/html/kdlp.underground.software/
MARKDOWN_ROOT=${KDLP_ROOT}/src
MARKDOWN_TARGET=${KDLP_ROOT}/${PATH_INFO}
if [ ! -f ${MARKDOWN_TARGET} ]; then
	MARKDOWN_TARGET=${KDLP_ROOT}/404.md
fi
echo -e "Content-Type: text/html\n\n"

cat ${KDLP_ROOT}/nav ${KDLP_ROOT}/header <(markdown ${MARKDOWN_TARGET})
