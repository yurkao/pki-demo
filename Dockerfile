FROM yurkao/openssl:1.0.2u-vuln
USER root
RUN touch "${OPENSSL_DIR}"/index "${OPENSSL_DIR}"/index.attr && echo 00 > "${OPENSSL_DIR}"/serial
CMD tail -F /dev/null

