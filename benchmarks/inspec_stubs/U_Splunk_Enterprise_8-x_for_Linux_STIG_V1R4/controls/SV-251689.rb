control 'SV-251689' do
  title 'Splunk Enterprise must use TLS 1.2 and SHA-2 or higher cryptographic algorithms.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

Splunk Enterprise, by default, is compliant with this requirement. But since the settings can be overridden, the check and fix text in this requirement is necessary.'
  desc 'check', 'Examine the configuration.

Check the following files in the $SPLUNK_HOME/etc/system/local folder:

inputs.conf   : Check is applicable to the indexer which may be a separate machine in a distributed environment.

Check for the following lines, if they do not exist, then the settings are compliant. If they exist, they must match the settings below or it is a finding:

sslVersions = tls1.2
ciphersuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256
ecdhCurves = prime256v1, secp384r1, secp521r1

outputs.conf  : Check is applicable to the forwarder which is always a separate machine in the environment. 

Check for the following lines, if they do not exist, then the settings are compliant. If they exist, they must match the settings below or it is a finding:

sslVersions = tls1.2
ciphersuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256
ecdhCurves = prime256v1, secp384r1, secp521r1

server.conf

Check for the following lines, if they do not exist, then the settings are compliant. If they exist, they must match the settings below or it is a finding:

sslVersions = tls1.2
sslVersionsForClient = tls1.2
ciphersuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES128-SHA256
ecdhCurves = prime256v1, secp384r1, secp521r1

web.conf : Check is applicable to search head or deployment server which may be a separate machine in a distributed environment.

Check for the following lines, if they do not exist, then the settings are compliant. If they exist, they must match the settings below or it is a finding:

sslVersions = tls1.2
ciphersuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256
ecdhCurves = prime256v1, secp384r1, secp521r1

Check the following file in the /etc/openldap folder:

ldap.conf

Check for the following lines, they must match the settings below or it is a finding:

#TLS_PROTOCOL_MIN: 3.1 for TLSv1.0, 3.2 for TLSv1.1, 3.3 for TLSv1.2.
TLS_PROTOCOL_MIN 3.3
TLS_CIPHER_SUITE ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256

Note: Splunk Enterprise must operate in FIPS mode to limit the algorithms allowed.'
  desc 'fix', 'Edit the following files in the $SPLUNK_HOME/etc/system/local folder:

inputs.conf   : Fix is applicable to the indexer which may be a separate machine in a distributed environment.

Check for the following lines, if they do not exist, then the settings are compliant. If they exist, they must match the settings below or be removed:

sslVersions = tls1.2
ciphersuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256
ecdhCurves = prime256v1, secp384r1, secp521r1

outputs.conf  : Check is applicable to the forwarder which is always a separate machine in the environment. 

Check for the following lines, if they do not exist, then the settings are compliant. If they exist, they must match the settings below or be removed:

sslVersions = tls1.2
ciphersuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256
ecdhCurves = prime256v1, secp384r1, secp521r1

server.conf

Check for the following lines, if they do not exist, then the settings are compliant. If they exist, they must match the settings below or be removed:

sslVersions = tls1.2
sslVersionsForClient = tls1.2
ciphersuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256:AES128-SHA256
ecdhCurves = prime256v1, secp384r1, secp521r1

web.conf : Check is applicable to search head or deployment server which may be a separate machine in a distributed environment.

Check for the following lines, if they do not exist, then the settings are compliant. If they exist, they must match the settings below or be removed:

sslVersions = tls1.2
ciphersuite = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256
ecdhCurves = prime256v1, secp384r1, secp521r1

Check the following file in the /etc/openldap folder:

ldap.conf

Check for the following lines, set to match the settings below:

#TLS_PROTOCOL_MIN: 3.1 for TLSv1.0, 3.2 for TLSv1.1, 3.3 for TLSv1.2.
TLS_PROTOCOL_MIN 3.3
TLS_CIPHER_SUITE ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-
SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-
AES128-SHA256:ECDHE-RSA-AES128-SHA256

Note: Splunk Enterprise must operate in FIPS mode to limit the algorithms allowed.'
  impact 0.7
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55127r819128_chk'
  tag severity: 'high'
  tag gid: 'V-251689'
  tag rid: 'SV-251689r879898_rule'
  tag stig_id: 'SPLK-CL-000430'
  tag gtitle: 'SRG-APP-000610-AU-000050'
  tag fix_id: 'F-55081r819129_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
