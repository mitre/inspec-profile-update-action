control 'SV-223140' do
  title 'ActiveX controls without prompt property must be used in approved domains only (Restricted Sites zone).'
  desc "This policy setting controls whether or not the user is prompted to allow ActiveX controls to run on websites other than the website that installed the ActiveX control. If the user were to disable the setting for the zone, malicious ActiveX controls could be executed without the user's knowledge. Disabling this setting would allow the possibility for malicious ActiveX controls to be executed from non-approved domains within this zone without the user's knowledge. Enabling this setting enforces the default value and prohibits the user from changing the value. Websites should be moved into another zone if permissions need to be changed."
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow only approved domains to use ActiveX controls without prompt' must be 'Enabled', and 'Enable' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "120b" is REG_DWORD = 3, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Allow only approved domains to use ActiveX controls without prompt' to 'Enabled', and select 'Enable' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24813r428970_chk'
  tag severity: 'medium'
  tag gid: 'V-223140'
  tag rid: 'SV-223140r879630_rule'
  tag stig_id: 'DTBI880-IE11'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24801r428971_fix'
  tag 'documentable'
  tag legacy: ['SV-59759', 'V-46893']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
