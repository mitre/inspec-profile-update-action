control 'SV-246847' do
  title 'The HYCU server must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Open a new HYCU Web UI browser tab and verify there is no warning prompt before proceeding to the Web UI logon page. 

If a warning appears in the web browser stating "Not secure", this is a finding.'
  desc 'fix', 'Log on to the HYCU Web UI and generate a CSR within the gear menu and "SSL Certificates" menu.
 
Submit this CSR to a DoD PKI authority to have a new certificate created. 

Note: By default, HYCU is configured with a self-signed certificate, but this can be replaced with a DoD-issued certificate. This certificate can be configured by logging on to the HYCU Web UI, going to the gear menu and "SSL Certificates" menu, and importing the DoD-issued certificate.'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50279r768203_chk'
  tag severity: 'medium'
  tag gid: 'V-246847'
  tag rid: 'SV-246847r768205_rule'
  tag stig_id: 'HYCU-CM-000003'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-50233r768204_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
