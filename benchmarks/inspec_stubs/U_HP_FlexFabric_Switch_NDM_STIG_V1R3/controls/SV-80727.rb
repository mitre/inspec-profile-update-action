control 'SV-80727' do
  title 'The HP FlexFabric Switch must notify the administrator, upon successful logon (access), of the location of last logon (terminal or IP address) in addition to the date and time of the last logon (access).'
  desc 'Administrators need to be aware of activity that occurs regarding their account. Providing them with information deemed important by the organization may aid in the discovery of unauthorized access or thwart a potential attacker. 

Organizations should consider the risks to the specific information system being accessed and the threats presented by the device to the environment when configuring this option. An excessive or unnecessary amount of information presented to the administrator at logon is not recommended.'
  desc 'check', 'Determine if the HP FlexFabric Switch notifies the administrator upon successful logon of the location of last logon (terminal or IP address) in addition to the date and time of the last logon. 

[HP] display password-control

Global password control configurations:
 Password control:                    Enabled

If the administrator is not notified of the location of last logon (terminal or IP address) upon successful logon, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to notify the administrator upon successful logon of the location of last logon (terminal or IP address).

[HP]  password-control enabled'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66883r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66237'
  tag rid: 'SV-80727r1_rule'
  tag stig_id: 'HFFS-ND-000093'
  tag gtitle: 'SRG-APP-000346-NDM-000291'
  tag fix_id: 'F-72313r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002250']
  tag nist: ['CM-6 b', 'AC-9 (4)']
end
