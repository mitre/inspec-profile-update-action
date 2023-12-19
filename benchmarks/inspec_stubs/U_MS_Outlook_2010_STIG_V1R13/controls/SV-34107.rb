control 'SV-34107' do
  title 'Outlook minimum encryption key length settings must be set.'
  desc 'This setting allows you to set the minimum key length for an encrypted e-mail message.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cyrptography “Minimum encryption settings” must be set to “Enabled: 168 bits".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value MinEncKey is REG_DWORD = 168, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cyrptography “Minimum encryption settings” to “Enabled: 168 bits".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34232r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26636'
  tag rid: 'SV-34107r1_rule'
  tag stig_id: 'DTOO316 - Outlook'
  tag gtitle: 'DTOO316 - Minimum encryption settings'
  tag fix_id: 'F-29922r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
