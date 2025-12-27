control 'SV-228436' do
  title 'The Add-In Trust Level must be configured.'
  desc 'All installed trusted COM addins can be trusted.  Exchange Settings for the addins still override if present and this option is selected.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security "Configure Add-In Trust Level" is set to "Enabled (Trust all loaded and installed COM addins)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value AddinTrust is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security "Configure Add-In Trust Level" to "Enabled (Trust all loaded and installed COM addins)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30669r497630_chk'
  tag severity: 'medium'
  tag gid: 'V-228436'
  tag rid: 'SV-228436r508021_rule'
  tag stig_id: 'DTOO236'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-30654r497631_fix'
  tag 'documentable'
  tag legacy: ['SV-85775', 'V-71151']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
