control 'SV-82923' do
  title 'The Mainframe Product must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'If the Mainframe Product is deployed in an unclassified environment, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product does not implement NSA-approved cryptography to protect classified information using an external security manager (ESM), this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to implement NSA-approved cryptography to protect classified information using an external security manager.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68965r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68433'
  tag rid: 'SV-82923r1_rule'
  tag stig_id: 'SRG-APP-000416-MFP-000269'
  tag gtitle: 'SRG-APP-000416-MFP-000269'
  tag fix_id: 'F-74549r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
