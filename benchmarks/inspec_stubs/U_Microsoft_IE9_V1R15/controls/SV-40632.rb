control 'SV-40632' do
  title 'All network paths (UNCs) for Intranet sites must be disallowed.'
  desc 'Some UNC paths could refer to servers not managed by the organization which means they could host malicious content and therefore, it is safest to not include all UNC paths in the Intranet Sites zone.  This policy setting controls whether URLs representing UNCs are mapped into the local Intranet security zone. If you enable this policy setting, all network paths are mapped into the Intranet Zone. If you disable this policy setting, network paths are not necessarily mapped into the Intranet Zone (other rules might map one there). If you do not configure this policy setting, users choose whether network paths are mapped into the Intranet Zone.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> "Intranet Sites: Include all network paths (UNCs)" must be “Disabled”.  

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap 

Criteria: If the value UNCAsIntranet is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> "Intranet Sites: Include all network paths (UNCs)" to “Disabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39370r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15504'
  tag rid: 'SV-40632r1_rule'
  tag stig_id: 'DTBI375'
  tag gtitle: "DTBI375 - Network paths (UNC's) - Intranet"
  tag fix_id: 'F-34484r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECSC-1'
end
