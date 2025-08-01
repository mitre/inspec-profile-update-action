control 'SV-83823' do
  title 'The NSX vCenter must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Verify a public key certificate is obtained from an appropriate certificate policy through an approved service provider is used on the vCenter Server.
 
Launch browser and go to the vSphere Web Client URL https://client-hostname/vsphere-client and verify the CA certificate is signed by an approved service provider.

If a public key certificate from an appropriate certificate policy through an approved service provider is not used, this is a finding.'
  desc 'fix', 'Configure the vCenter Server to obtain its public key certificates in offline mode from an appropriate certificate policy through an approved service provider.

Replace default certificates with certificate authority signed SSL certificates in vSphere 6.0 with KB 2111219.'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69659r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69219'
  tag rid: 'SV-83823r1_rule'
  tag stig_id: 'VNSX-ND-000141'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-75405r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
