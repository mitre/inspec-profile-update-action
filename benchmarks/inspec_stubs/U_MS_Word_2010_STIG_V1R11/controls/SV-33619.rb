control 'SV-33619' do
  title 'Warning Bar settings for VBA macros must be configured.'
  desc 'When users open files containing VBA Macros, applications open the files with the macros disabled and displays the Trust Bar with a warning that macros are present and have been disabled. Users may then enable these macros by clicking Options on the Trust Bar and selecting the option to enable them. Disabling or not configuring this setting may allow dangerous macros to become active on user computers or the network.'
  desc 'check', 'NOTE: If VBA support is not installed, this check is Not Applicable.

The policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security -> Trust Center “VBA Macro Notification Settings” must be “Enabled (Disable all with notification)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\word\\security

Criteria: If the value VBAWarnings is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security -> Trust Center “VBA Macro Notification Settings”  to “Enabled (Disable all with notification)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2010'
  tag check_id: 'C-34084r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17545'
  tag rid: 'SV-33619r2_rule'
  tag stig_id: 'DTOO304 - Word'
  tag gtitle: 'DTOO304 - VBA Macro Warning settings'
  tag fix_id: 'F-29761r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
