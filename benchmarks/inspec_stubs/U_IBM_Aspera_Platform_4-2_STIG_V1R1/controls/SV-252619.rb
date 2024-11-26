control 'SV-252619' do
  title 'The IBM Aspera High-Speed Transfer Endpoint must have a master-key set to encrypt the dynamic token encryption key.'
  desc 'Configuring the network element to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network element. Security-related parameters are those parameters impacting the security state of the network element, including the parameters required to satisfy other security control requirements. For the network element, security-related parameters include settings for network traffic management configurations.

The master key must be a unique random 256-bit key. The example below uses openssl to generate the key. This Redis master key will be used to encrypt the dynamic token encryption key.

'
  desc 'check', 'Verify the IBM High-Speed Transfer Endpoint has a master-key set to encrypt the dynamic token encryption key with the following commands:

$ sudo /opt/aspera/bin/askmcli -u <transferuser> -H Redis-master-key

v0: (SHA-512) 6fcb5c284590f67af12334cf27f94a6dc5fb2f27627b9ba8dc20c210df3edd7a596cd3c9961a5c36bfd8e57a9ae15a6859559f8e11c3059704859cabb59d8340

$ sudo /opt/aspera/bin/askmcli -u asperadaemon -H Redis-master-key

v0: (SHA-512) 6fcb5c284590f67af12334cf27f94a6dc5fb2f27627b9ba8dc20c210df3edd7a596cd3c9961a5c36bfd8e57a9ae15a6859559f8e11c3059704859cabb59d8340

If either command returns "No records found for Redis-master-key", this is a finding.'
  desc 'fix', %q(Configure the IBM High-Speed Transfer Endpoint to set a master-key to encrypt the dynamic token encryption key with the following command:

$ sudo echo -n "`openssl rand -base64 32`" | sudo /opt/aspera/bin/askmscli -s Redis-master-key

For each transfer user with a token encryption key, initialize the user's keystore with the following command:

$ sudo /opt/aspera/bin/askmscli -i -u <transferuser>

Initialize the keystore for the asperadaemon user that runs asperanoded with the following command:

$ sudo /opt/aspera/bin/askmscli -i -u asperadaemon

Restart the IBM Aspera Node service to activate the changes.

$ sudo systemctl restart asperanoded.service)
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56075r818025_chk'
  tag severity: 'medium'
  tag gid: 'V-252619'
  tag rid: 'SV-252619r818027_rule'
  tag stig_id: 'ASP4-TE-030170'
  tag gtitle: 'SRG-NET-000063-ALG-000012'
  tag fix_id: 'F-56025r818026_fix'
  tag satisfies: ['SRG-NET-000063-ALG-000012', 'SRG-NET-000510-ALG-000025', 'SRG-NET-000510-ALG-000111']
  tag 'documentable'
  tag cci: ['CCI-001453', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'SC-13 b']
end
