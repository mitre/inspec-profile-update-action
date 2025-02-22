control 'SV-234555' do
  title 'The UEM server must configure web management tools with FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Nonlocal maintenance and diagnostic activities are activities conducted by individuals communicating through either an external network (e.g., the internet) or an internal network.'
  desc 'check', 'Verify the UEM server web management tools use a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions.

If the UEM server web management tools do not use FIPS-validated Advanced Encryption Standard (AES) cipher block algorithms to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions, this is a finding.'
  desc 'fix', 'Configure the UEM server web management tools with a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37740r851630_chk'
  tag severity: 'high'
  tag gid: 'V-234555'
  tag rid: 'SV-234555r879785_rule'
  tag stig_id: 'SRG-APP-000412-UEM-000283'
  tag gtitle: 'SRG-APP-000412'
  tag fix_id: 'F-37705r615309_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
