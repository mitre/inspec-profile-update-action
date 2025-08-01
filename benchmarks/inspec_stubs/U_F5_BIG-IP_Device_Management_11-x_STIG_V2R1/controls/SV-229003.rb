control 'SV-229003' do
  title 'The BIG-IP appliance must be configured to notify the administrator, upon successful logon (access), of the location of last logon (terminal or IP address) in addition to the date and time of the last logon (access).'
  desc 'Administrators need to be aware of activity that occurs regarding their account. Providing them with information deemed important by the organization may aid in the discovery of unauthorized access or thwart a potential attacker. 

Organizations should consider the risks to the specific information system being accessed and the threats presented by the device to the environment when configuring this option. An excessive or unnecessary amount of information presented to the administrator at logon is not recommended.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that is able to notify the administrator upon successful logon of the location of last logon (terminal or IP address) in addition to the date and time of the last logon.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server type that is able to notify the administrator upon successful logon of the location of last logon (terminal or IP address) in addition to the date and time of the last logon.

If the administrator is not notified of the location of last logon (terminal or IP address) upon successful logon (terminal or IP address) in addition to the date and time of the last logon, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server that is able to notify the administrator upon successful logon of the location of last logon (terminal or IP address) in addition to the date and time of the last logon.'
  impact 0.3
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31318r518054_chk'
  tag severity: 'low'
  tag gid: 'V-229003'
  tag rid: 'SV-229003r557520_rule'
  tag stig_id: 'F5BI-DM-000187'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31295r518055_fix'
  tag 'documentable'
  tag legacy: ['V-60197', 'SV-74627']
  tag cci: ['CCI-000366', 'CCI-002250']
  tag nist: ['CM-6 b', 'AC-9 (4)']
end
