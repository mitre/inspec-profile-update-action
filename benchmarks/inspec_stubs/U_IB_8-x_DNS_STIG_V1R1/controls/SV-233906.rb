control 'SV-233906' do
  title 'The Infoblox DNS server must implement NIST FIPS-validated cryptography for provisioning digital signatures, generating cryptographic hashes, and protecting unclassified information requiring confidentiality.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Note: For Infoblox DNS systems on a classified network, this requirement is Not Applicable.  

Note: For Infoblox Grids that run in FIPS mode, this requirement is Not Applicable. Refer to the Administrator Guide for more information on FIPS Mode.  

1. Navigate to Data Management >> DNS >> Grid DNS properties. 
2. Toggle Advanced Mode and click on the "DNSSEC" tab.  
3. Validate that all Key Signing Keys (KSKs) and Zone Signing Keys (ZSKs) use FIPS-approved algorithms.  
4. When complete, click "Cancel" to exit the "Properties" screen. 

If non-FIPS-approved algorithms are in use, this is a finding.'
  desc 'fix', 'Note: Ensure DNSSEC is configured to meet all other STIG requirements prior to signing a zone to avoid signing with an unapproved configuration.

1. Navigate to Data Management >> DNS >> Grid DNS properties. 
2. Toggle Advanced Mode and click on the "DNSSEC" tab.  
3. Configure FIPS-compliant algorithms. 
4. Follow manual key rollover procedures and update all non-compliant KSKs and ZSKs to use FIPS-approved algorithms.'
  impact 0.7
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37091r611238_chk'
  tag severity: 'high'
  tag gid: 'V-233906'
  tag rid: 'SV-233906r621666_rule'
  tag stig_id: 'IDNS-8X-700001'
  tag gtitle: 'SRG-APP-000514-DNS-000075'
  tag fix_id: 'F-37056r611239_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
