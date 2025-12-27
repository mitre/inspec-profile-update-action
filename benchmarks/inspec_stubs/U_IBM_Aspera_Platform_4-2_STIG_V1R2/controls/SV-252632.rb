control 'SV-252632' do
  title 'The IBM Aspera High-Speed Transfer Server must enable content protection for each transfer user by encrypting passphrases used for server-side encryption at rest (SSEAR).'
  desc 'Configuring the network element to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network element. Security-related parameters are those parameters impacting the security state of the network element, including the parameters required to satisfy other security control requirements. For the network element, security-related parameters include settings for network traffic management configurations.

The askmscli tool sets content-protection secrets only for each user, not for groups and not for all users on a node. Each transfer user requires their own content-protection secret for SSEAR.'
  desc 'check', 'Verify the IBM High-Speed Transfer Server enables content protection for each transfer user by encrypting passphrases used for SSEAR with the following command:

$ sudo /opt/aspera/bin/askmcli -u <transferuser> -H ssear

v0: (SHA-512) 6fcb5c284590f67af12334cf27f94a6dc5fb2f27627b9ba8dc20c210df3edd7a596cd3c9961a5c36bfd8e57a9ae15a6859559f8e11c3059704859cabb59d8340

If the command returns "No records found for ssear", this is a finding.'
  desc 'fix', 'Configure the IBM High-Speed Transfer Server to enable content protection for each transfer user by encrypting passphrases used for SSEAR with the following command:

$ sudo /opt/aspera/bin/askmscli -u <transferuser> -s ssear'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56088r818064_chk'
  tag severity: 'medium'
  tag gid: 'V-252632'
  tag rid: 'SV-252632r831527_rule'
  tag stig_id: 'ASP4-TS-020160'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56038r818065_fix'
  tag 'documentable'
  tag cci: ['CCI-002475', 'CCI-002476']
  tag nist: ['SC-28 (1)', 'SC-28 (1)']
end
