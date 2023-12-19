control 'SV-252198' do
  title 'The HPE Nimble must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Type "cert --list". Review the output to confirm that the custom-ca and custom certificates exist, and the "Use" values specified for HTTPS and APIS are both "custom". If not, this is a finding.'
  desc 'fix', 'To create and import a custom, CA-signed certificate follow these steps:

1. Type "cert --gen custom-csr". Copy the displayed CSR and submit it to an appropriate signing authority.
2. Type "cert --import custom-ca" and paste the PEM-encoded CA certificate chain as input to the command.
3. Type "cert --import custom" and paste the signed certificate obtained from the CA.'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55654r814072_chk'
  tag severity: 'medium'
  tag gid: 'V-252198'
  tag rid: 'SV-252198r814074_rule'
  tag stig_id: 'HPEN-NM-000130'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-55604r814073_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
