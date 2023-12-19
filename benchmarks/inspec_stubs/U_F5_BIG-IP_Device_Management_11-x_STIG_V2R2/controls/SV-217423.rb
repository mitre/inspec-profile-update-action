control 'SV-217423' do
  title 'The BIG-IP appliance must be configured to obtain its public key certificates from an appropriate certificate policy through a DoD-approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Verify the BIG-IP appliance is configured to obtain public key certificates from an appropriate certificate policy through a DoD-approved service provider.

Navigate to the BIG-IP System manager >> System >> Device Certificates >> Device Certificate.

Verify the device certificate has been obtained from an approved service provider.

If the BIG-IP appliance does not obtain its public key certificates from an appropriate certificate policy through a DoD-approved service provider, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to obtain its public key certificates from an appropriate certificate policy through a DoD-approved service provider.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18648r290823_chk'
  tag severity: 'medium'
  tag gid: 'V-217423'
  tag rid: 'SV-217423r879887_rule'
  tag stig_id: 'F5BI-DM-000283'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-18646r290824_fix'
  tag 'documentable'
  tag legacy: ['SV-74669', 'V-60239']
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
