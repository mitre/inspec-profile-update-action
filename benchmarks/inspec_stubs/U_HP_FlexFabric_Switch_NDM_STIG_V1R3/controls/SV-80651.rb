control 'SV-80651' do
  title 'Upon successful logon, the HP FlexFabric Switch must notify the administrator of the date and time of the last logon.'
  desc 'Administrators need to be aware of activity that occurs regarding their network device management account. Providing administrators with information regarding the date and time of their last successful logon allows them to determine if any unauthorized activity has occurred. This incorporates all methods of logon, including, but not limited to, SSH, HTTP, HTTPS, and physical connectivity.'
  desc 'check', "Determine if the HP FlexFabric Switch is configured to notify the administrator of the date and time of their last logon. Once the logon credentials have been entered the system should display the previous logon information for the user:

Log on as: admin
admin@15.252.78.64's password:
Your logon failures since the last successful logon:
 Wed May 27 10:06:04 2015
 Wed May 27 10:06:09 2015

Last successfully logon time: Wed May 27 10:45:51 2015

If the administrator is not notified of the date and time of the last logon upon successful logon, this is a finding."
  desc 'fix', 'Configure the HP FlexFabric Switch to notify the administrator of the date and time of the last successful logon:

[HP]  password-control enable'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66807r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66161'
  tag rid: 'SV-80651r1_rule'
  tag stig_id: 'HFFS-ND-000018'
  tag gtitle: 'SRG-APP-000075-NDM-000217'
  tag fix_id: 'F-72237r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000052', 'CCI-000366']
  tag nist: ['AC-9', 'CM-6 b']
end
