control 'SV-91719' do
  title 'The DBN-6300 must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.

Self-signed certificates are not allowed.'
  desc 'check', 'Verify that the Public Key Certificate is installed and has been obtained from an appropriate certificate policy through an approved service provider.

Navigate to CLI and verify that there is a registry entry similar to below:

Reg set /sysconfig/tls/trustedcas EOF
(enter/paste certificate here)
EOF

If an entry is not found in the registry with the appropriate certificate, this is a finding.'
  desc 'fix', 'Verify that the Public Key Certificate is installed and has been obtained from an appropriate certificate policy through an approved service provider.

Set the trusted-ca variable within the DBN-6300 through the CLI.

This value is set with the following registry entry in the CLI:

Reg set /sysconfig/tls/trustedcas EOF
(enter/paste certificate here)
EOF'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76649r1_chk'
  tag severity: 'medium'
  tag gid: 'V-77023'
  tag rid: 'SV-91719r1_rule'
  tag stig_id: 'DBNW-DM-000141'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-83719r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
