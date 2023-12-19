control 'SV-223080' do
  title 'All network paths (UNCs) for Intranet sites must be disallowed.'
  desc 'Some UNC paths could refer to servers not managed by the organization, which means they could host malicious content; and therefore, it is safest to not include all UNC paths in the Intranet Sites zone. This policy setting controls whether URLs representing UNCs are mapped into the local Intranet security zone. If you enable this policy setting, all network paths are mapped into the Intranet Zone. If you disable this policy setting, network paths are not necessarily mapped into the Intranet Zone (other rules might map one there). If you do not configure this policy setting, users choose whether network paths are mapped into the Intranet Zone.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> 'Intranet Sites: Include all network paths (UNCs)' must be 'Disabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap Criteria: If the value "UNCAsIntranet" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> 'Intranet Sites: Include all network paths (UNCs)' to 'Disabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24753r428790_chk'
  tag severity: 'medium'
  tag gid: 'V-223080'
  tag rid: 'SV-223080r879887_rule'
  tag stig_id: 'DTBI375-IE11'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24741r428791_fix'
  tag 'documentable'
  tag legacy: ['SV-59499', 'V-46635']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
