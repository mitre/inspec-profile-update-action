control 'SV-33424' do
  title 'Warning Bar settings for VBA macros must be configured.'
  desc 'When users open files containing VBA Macros, applications open the files with the macros disabled and displays the Trust Bar with a warning that macros are present and have been disabled. Users may then enable these macros by clicking Options on the Trust Bar and selecting the option to enable them. Disabling or not configuring this setting may allow dangerous macros to become active on user computers or the network.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Access 2010-> Application Settings -> Security -> Trust Center “VBA Macro Notification Settings” must be “Enabled (Disabled all with notifications)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\access\\security

Criteria: If the value VBAWarnings is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Access 2010 -> Application Settings -> Security -> Trust Center “VBA Macro Warning Settings” to “Enabled (Disabled all with notifications)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Access 2010'
  tag check_id: 'C-33907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17545'
  tag rid: 'SV-33424r1_rule'
  tag stig_id: 'DTOO304 - Access'
  tag gtitle: 'DTOO304 - VBA Macro Warning settings'
  tag fix_id: 'F-29596r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
