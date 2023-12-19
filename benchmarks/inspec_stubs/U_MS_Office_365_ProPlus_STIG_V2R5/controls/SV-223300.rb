control 'SV-223300' do
  title 'The Local Machine Zone Lockdown Security must be enabled in all Office programs.'
  desc "Internet Explorer places restrictions on each web page users can use the browser to open. Web pages on a user's local computer have the fewest security restrictions and reside in the Local Machine zone, making this security zone a prime target for malicious users and code. Disabling or not configuring this setting could allow pages in the Internet zone to navigate to pages in the Local Machine zone to then run code to elevate privileges. This could allow malicious code or users to become active on user computers or the network."
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Local Machine Zone Lockdown Security is set to "Enabled" and the check box is selected for every installed Office program.

Use the Windows Registry Editor to navigate to the following key:

HKLM\\software\\microsoft\\internet explorer\\main\\featurecontrol\\feature_localmachine_lockdown

If the value for all installed Office programs is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Local Machine Zone Lockdown to "Enabled" and select the check boxes for  all installed Office programs.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24973r442119_chk'
  tag severity: 'medium'
  tag gid: 'V-223300'
  tag rid: 'SV-223300r508019_rule'
  tag stig_id: 'O365-CO-000018'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24961r442120_fix'
  tag 'documentable'
  tag legacy: ['SV-108779', 'V-99675']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
