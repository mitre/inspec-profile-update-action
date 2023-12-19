control 'SV-234248' do
  title 'All UEM Agent cryptography supporting DoD functionality must be FIPS 140-2 validated.'
  desc 'Unapproved cryptographic algorithms cannot be relied on to provide confidentiality or integrity, and DoD data could be compromised as a result. The most common vulnerabilities with cryptographic modules are those associated with poor implementation. FIPS 140-2 validation provides assurance that the relevant cryptography has been implemented correctly. FIPS 140-2 validation is also a strict requirement for use of cryptography in the federal government for protecting unclassified data.

'
  desc 'check', 'Verify all UEM Agent cryptography supporting DoD functionality is FIPS 140-2 validated.

If all UEM Agent cryptography supporting DoD functionality is not FIPS 140-2 validated, this is a finding.'
  desc 'fix', 'Configure the UEM Agent cryptography supporting DoD functionality for FIPS 140-2 mode.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37433r612050_chk'
  tag severity: 'high'
  tag gid: 'V-234248'
  tag rid: 'SV-234248r617402_rule'
  tag stig_id: 'SRG-APP-000555-UEM-100014'
  tag gtitle: 'SRG-APP-000555'
  tag fix_id: 'F-37398r612051_fix'
  tag satisfies: ['FCS\nReference: PP-UEM-404200']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
