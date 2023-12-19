control 'SV-33525' do
  title 'Users customizing attachment security settings must be prevented.'
  desc 'All installed trusted COM addins can be trusted.  Exchange Settings for the addins still override if present and this option is selected'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security “Prevent users from customizing attachment security settings” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook

Criteria: If the value DisallowAttachmentCustomization is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security “Prevent users from customizing attachment security settings” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34012r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17766'
  tag rid: 'SV-33525r1_rule'
  tag stig_id: 'DTOO238 - Outlook'
  tag gtitle: "DTOO238 - Prev't users customizing security set"
  tag fix_id: 'F-29700r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
