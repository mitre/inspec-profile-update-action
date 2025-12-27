control 'SV-79677' do
  title 'The DataPower Gateway must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Go to Objects >> Crypto Configuration >> Crypto Certificate (for certs) or Crypto Key (for keys) to verify external keys/certs on the encrypted flash or FIPS 140-2 Level 3 HSM. If none exist, this is a finding.'
  desc 'fix', 'Go to Objects >> Crypto Configuration >> Crypto Certificate (for certs) or Crypto Key (for keys) to upload external keys/certs to the encrypted flash or FIPS 140-2 Level 3 HSM.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65187'
  tag rid: 'SV-79677r1_rule'
  tag stig_id: 'WSDP-NM-000141'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-71127r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
