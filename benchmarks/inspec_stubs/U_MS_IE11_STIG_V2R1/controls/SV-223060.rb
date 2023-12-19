control 'SV-223060' do
  title 'File downloads must be disallowed (Restricted Sites zone).'
  desc 'Sites located in the Restricted Sites Zone are more likely to contain malicious payloads and therefore downloads from this zone should be blocked. Files should not be able to be downloaded from sites that are considered restricted. This policy setting allows you to manage whether file downloads are permitted from the zone. This option is determined by the zone of the page with the link causing the download, not the zone from which the file is delivered.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow file downloads' must be 'Enabled', and 'Disable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1803" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow file downloads' to 'Enabled', and select 'Disable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24733r428730_chk'
  tag severity: 'medium'
  tag gid: 'V-223060'
  tag rid: 'SV-223060r428732_rule'
  tag stig_id: 'DTBI119-IE11'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-24721r428731_fix'
  tag 'documentable'
  tag legacy: ['SV-59447', 'V-46583']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
