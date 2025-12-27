control 'SV-82997' do
  title 'The Mainframe Product must audit detected potential integrity violations.'
  desc 'Without an audit capability, an integrity violation may not be detected. Organizations select response actions based on types of software, specific software, or information for which there are potential integrity violations. The integrity verification application must have the capability to audit and it must be enabled.'
  desc 'check', 'If the Mainframe Product has no function or capability for integrity verification, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to audit detected potential integrity violations, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to audit detected potential integrity violations.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69039r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68507'
  tag rid: 'SV-82997r1_rule'
  tag stig_id: 'SRG-APP-000484-MFP-000383'
  tag gtitle: 'SRG-APP-000484-MFP-000383'
  tag fix_id: 'F-74623r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002723']
  tag nist: ['SI-7 (8)']
end
