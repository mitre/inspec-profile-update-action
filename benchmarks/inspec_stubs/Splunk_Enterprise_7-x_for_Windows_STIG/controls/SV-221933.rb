control 'SV-221933' do
  title 'Splunk Enterprise must use TLS 1.2 and SHA-2 or higher cryptographic algorithms.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

Splunk Enterprise, by default, is compliant with this requirement. But since the settings can be overridden, the check and fix text in this requirement is necessary.'
  desc 'check', 'In the Splunk installation folder, check the following files in the $SPLUNK_HOME/etc/system/local folder:

(Note that these files may exist in one of the following folders or its subfolders:
$SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/etc/slave-apps/)

inputs.conf

Check for the following lines; if they do not exist, the settings are compliant. If they exist, they must match the settings below:

 sslVersions = tls1.2
 cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
 SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
 AES128-SHA256:ECDHE-RSA-AES128-SHA256
 ecdhCurves = prime256v1, secp384r1, secp521r1

outputs.conf

Check for the following lines; if they do not exist, the settings are compliant. If they exist, they must match the settings below:

 sslVersions = tls1.2
 cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
 SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
 AES128-SHA256:ECDHE-RSA-AES128-SHA256
 ecdhCurves = prime256v1, secp384r1, secp521r1

server.conf

Check for the following lines; if they do not exist, the settings are compliant. If they exist, they must match the settings below:

 sslVersions = tls1.2
 sslVersionsForClient = tls1.2
 cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
 SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
 AES128-SHA256:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES128-SHA256
 ecdhCurves = prime256v1, secp384r1, secp521r1

web.conf

Check for the following lines; if they do not exist, the settings are compliant. If they exist, they must match the settings below:

 sslVersions = tls1.2
 cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
 SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
 AES128-SHA256:ECDHE-RSA-AES128-SHA256
 ecdhCurves = prime256v1, secp384r1, secp521r1

Check the following file in the $SPLUNK_HOME/etc/openldap folder:

ldap.conf

Check for the following lines; they must match the settings below:

 #TLS_PROTOCOL_MIN: 3.1 for TLSv1.0, 3.2 for TLSv1.1, 3.3 for TLSv1.2.
 TLS_PROTOCOL_MIN 3.3
 TLS_CIPHER_SUITE ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
 SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
 AES128-SHA256:ECDHE-RSA-AES128-SHA256

If any of the above settings do not match, this is a finding.'
  desc 'fix', 'In the Splunk installation folder, check the following files in the $SPLUNK_HOME/etc/system/local folder:

(Note that these files may exist in one of the following folders or its subfolders:
$SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/etc/slave-apps/)

inputs.conf

Check for the following lines; if they do not exist, the settings are compliant. If they exist, they must match the settings below or be removed:

 sslVersions = tls1.2
 cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
 SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
 AES128-SHA256:ECDHE-RSA-AES128-SHA256
 ecdhCurves = prime256v1, secp384r1, secp521r1

outputs.conf

Check for the following lines; if they do not exist, the settings are compliant. If they exist, they must match the settings below or be removed:

 sslVersions = tls1.2
 cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
 SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
 AES128-SHA256:ECDHE-RSA-AES128-SHA256
 ecdhCurves = prime256v1, secp384r1, secp521r1

server.conf

Check for the following lines; if they do not exist, the settings are compliant. If they exist, they must match the settings below or be removed:

 sslVersions = tls1.2
 sslVersionsForClient = tls1.2
 cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
 SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
 AES128-SHA256:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES128-SHA256
 ecdhCurves = prime256v1, secp384r1, secp521r1

web.conf

Check for the following lines; if they do not exist, the settings are compliant. If they exist, they must match the settings below or be removed:

 sslVersions = tls1.2
 cipherSuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
 SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
 AES128-SHA256:ECDHE-RSA-AES128-SHA256
 ecdhCurves = prime256v1, secp384r1, secp521r1

Check the following file in the $SPLUNK_HOME/etc/openldap folder:

ldap.conf

Check for the following lines; they must match the settings below:

 #TLS_PROTOCOL_MIN: 3.1 for TLSv1.0, 3.2 for TLSv1.1, 3.3 for TLSv1.2.
 TLS_PROTOCOL_MIN 3.3
 TLS_CIPHER_SUITE ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
 SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
 AES128-SHA256:ECDHE-RSA-AES128-SHA256'
  impact 0.7
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23647r420267_chk'
  tag severity: 'high'
  tag gid: 'V-221933'
  tag rid: 'SV-221933r879898_rule'
  tag stig_id: 'SPLK-CL-000050'
  tag gtitle: 'SRG-APP-000610-AU-000050'
  tag fix_id: 'F-23636r420268_fix'
  tag 'documentable'
  tag legacy: ['SV-111387', 'V-102439']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
