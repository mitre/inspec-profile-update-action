control 'SV-33932' do
  title 'The Add-In Trust Level must be configured.'
  desc 'Under normal circumstances the installed COM add-ins are applications that have been approved and intentionally deployed by the organization and therefore they should not pose a security threat.  However, if malware has infected systems it is possible that the malware will use the COM add-in feature to perform unauthorized actions. This setting enforces the default configuration, and therefore is unlikely to cause significant usability issues for most users.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security “Configure Add-In Trust Level” must be set to “Enabled (Trust all loaded and installed COM addins)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value AddinTrust is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security “Configure Add-In Trust Level” to “Enabled (Trust all loaded and installed COM addins)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34374r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17566'
  tag rid: 'SV-33932r1_rule'
  tag stig_id: 'DTOO236 - Outlook'
  tag gtitle: 'DTOO236 - Add-In Trust Level'
  tag fix_id: 'F-30010r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Exchange Settings for the addins still override if present and this option is selected.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
