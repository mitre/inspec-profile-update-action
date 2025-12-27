control 'SV-251679' do
  title 'Splunk Enterprise must use organization-level authentication to uniquely identify and authenticate users.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be uniquely identified and authenticated to prevent potential misuse and compromise of the system. 

Sharing of accounts prevents accountability and non-repudiation. Organizational users must be uniquely identified and authenticated for all accesses.'
  desc 'check', 'This check is performed on the machine used as a search head or a deployment server, which may be a separate machine in a distributed environment.

Navigate to the $SPLUNK_HOME/etc/system/local/ directory.

View the authentication.conf file.

If the authentication.conf file does not exist, this is a finding.

In the authentication.conf file, verify minimum settings similar to the example below. If any minimum settings are not configured, this is a finding.

If using LDAP:

[authentication]
authType = LDAP
authSettings = <ldap_strategy>

[<ldap_strategy>]
host = <LDAP server>
port = <LDAP port>
sslEnabled = 1

Check the following file in the $SPLUNK_HOME/etc/openldap folder:

ldap.conf

If the file does not exist, this is a finding.

Check for the following lines. If any are missing or do not match the settings below, this is a finding.

TLS_REQCERT
TLS_CACERT <path to SSL certificate>
TLS_PROTOCOL_MIN 3.3
TLS_CIPHER_SUITE ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256

If using SAML:

[authentication]
authType = SAML
authSettings = <saml_strategy>
[<saml_strategy>]
entityId = <saml entity>
idpSSOUrl = <saml URL>
idpCertPath = <path to certificate>

Open the Splunk Web console.

Select Settings >> Access Controls >> Users. 

Verify that no user accounts exist with Authentication system set to Splunk except an account of last resort. They must all be set to LDAP or SAML.

If any user accounts have Authentication system set to Splunk, with the exception of one emergency account of last resort, this is a finding.'
  desc 'fix', 'This configuration is performed on the machine used as a search head or a deployment server, which may be a separate machine in a distributed environment.

Navigate to the $SPLUNK_HOME/etc/system/local/ directory.

Edit the authentication.conf file.

If the authentication.conf file does not exist, copy the file from $SPLUNK_HOME/etc/system/default to the $SPLUNK_HOME/etc/system/local directory.

Configure minimum settings similar to the example below for using LDAP or SAML.

If using LDAP:

[authentication]
authType = LDAP
authSettings = <ldap_strategy>

[<ldap_strategy>]
host = <LDAP server>
port = <LDAP port>
sslEnabled = 1

Edit the following file in the $SPLUNK_HOME/etc/openldap folder:

ldap.conf

Configure the following lines for your certificate.

TLS_REQCERT
TLS_CACERT <path to SSL certificate>
TLS_PROTOCOL_MIN 3.3
TLS_CIPHER_SUITE ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256

If using SAML:

[authentication]
authType = SAML
authSettings = <saml_strategy>
[<saml_strategy>]
entityId = <saml entity>
idpSSOUrl = <saml URL>
idpCertPath = <path to certificate>

After configuring LDAP or SAML, open the Splunk Web console.

Select Settings >> Access Controls >> Users. 

Create appropriate LDAP and SAML users and groups for the environment.

Delete any user account with Authentication system set to Splunk, with the exception of one emergency account of last resort. Splunk will prevent the user from deleting an LDAP or SAML account.'
  impact 0.7
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55117r819101_chk'
  tag severity: 'high'
  tag gid: 'V-251679'
  tag rid: 'SV-251679r879589_rule'
  tag stig_id: 'SPLK-CL-000320'
  tag gtitle: 'SRG-APP-000148-AU-002270'
  tag fix_id: 'F-55071r819102_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
