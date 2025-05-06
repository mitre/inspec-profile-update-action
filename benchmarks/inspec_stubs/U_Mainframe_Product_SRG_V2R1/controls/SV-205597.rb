control 'SV-205597' do
  title 'The Mainframe Product must audit detected potential integrity violations.'
  desc 'Without an audit capability, an integrity violation may not be detected. Organizations select response actions based on types of software, specific software, or information for which there are potential integrity violations. The integrity verification application must have the capability to audit and it must be enabled.'
  desc 'check', 'If the Mainframe Product has no function or capability for integrity verification, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to audit detected potential integrity violations, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to audit detected potential integrity violations.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5863r300018_chk'
  tag severity: 'medium'
  tag gid: 'V-205597'
  tag rid: 'SV-205597r851362_rule'
  tag stig_id: 'SRG-APP-000484-MFP-000383'
  tag gtitle: 'SRG-APP-000484'
  tag fix_id: 'F-5863r300019_fix'
  tag 'documentable'
  tag legacy: ['SV-82997', 'V-68507']
  tag cci: ['CCI-002723']
  tag nist: ['SI-7 (8)']
end
