#! /bin/bash
printf "\
set keycloak_tls_keystore_password=${PASSWORD} >> $JBOSS_HOME/bin/.jbossclirc\n\
set keycloak_tls_keystore_file=${KEYSTORES_STORAGE}/${JKS_KEYSTORE_FILE} >> $JBOSS_HOME/bin/.jbossclirc\n\
set configuration_file=standalone.xml >> $JBOSS_HOME/bin/.jbossclirc\n\
set configuration_file=standalone-ha.xml >> $JBOSS_HOME/bin/.jbossclirc
set keycloak_tls_truststore_password=${PASSWORD} >> $JBOSS_HOME/bin/.jbossclirc\n\
set keycloak_tls_truststore_file=${KEYSTORES_STORAGE}/${JKS_TRUSTSTORE_FILE} >> $JBOSS_HOME/bin/.jbossclirc\n\
set configuration_file=standalone.xml >> $JBOSS_HOME/bin/.jbossclirc\n\
set configuration_file=standalone-ha.xml >> $JBOSS_HOME/bin/.jbossclirc\n\
" > .clirc
