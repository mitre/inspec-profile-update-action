control 'SV-53232' do
  title 'Warning Bar settings for VBA macros must be configured.'
  desc 'When users open files containing VBA macros, applications open the files with the macros disabled and displays the Trust Bar with a warning that macros are present and have been disabled. Users may then enable these macros by clicking Options on the Trust Bar and selecting the option to enable them. Disabling or not configuring this setting may allow dangerous macros to become active on user computers or the network.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Project 2013 -> Project Options -> Security ->  Trust Center -> "VBA Macro Notification Settings" is set to "Enabled: Disable all with notification".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\15.0\\ms project\\security

Criteria: If the value vbawarnings is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the  policy value for User Configuration -> Administrative Templates -> Microsoft Project 2013 -> Project Options -> Security ->  Trust Center -> "VBA Macro Notification Settings" must be set to "Enabled: Disable all with notification".'
  impact 0.5
  ref 'DPMS Target Microsoft Project 2013'
  tag check_id: 'C-47539r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40890'
  tag rid: 'SV-53232r1_rule'
  tag stig_id: 'DTOO304'
  tag gtitle: 'DTOO304 - VBA Macro Warning settings'
  tag fix_id: 'F-46159r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
