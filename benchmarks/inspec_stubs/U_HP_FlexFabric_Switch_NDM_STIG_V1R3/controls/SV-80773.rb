control 'SV-80773' do
  title 'The HP FlexFabric Switch must notify the administrator of the number of successful logon attempts occurring during an organization-defined time period.'
  desc 'Administrators need to be aware of activity that occurs regarding their network device management account. Providing administrators with information regarding the date and time of their last successful logon allows the administrator to determine if any unauthorized activity has occurred. This incorporates all methods of logon including, but not limited to, SSH, HTTP, HTTPS, and physical connectivity. The organization-defined time period is dependent on the frequency with which administrators typically log on to the HP FlexFabric Switch.'
  desc 'check', "Determine if the HP FlexFabric Switch notifies the administrator of the number of successful logon attempts occurring during an organization-defined time period. Once the logon credentials have been entered, the system should display the previous logon information for the user:

Log on as: admin
admin@15.252.78.64's password:
Your logon failures since the last successful logon:
 Wed May 27 10:06:04 2015
 Wed May 27 10:06:09 2015

Last successfully logon time: Wed May 27 10:45:51 2015

If the administrator is not notified of the number of successful logon attempts occurring during an organization-defined time period, this is a finding."
  desc 'fix', 'Configure the HP FlexFabric Switch to notify the administrator of the date and time of the last unsuccessful logon: 

[HP]  password-control enable'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66929r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66283'
  tag rid: 'SV-80773r1_rule'
  tag stig_id: 'HFFS-ND-000129'
  tag gtitle: 'SRG-APP-000516-NDM-000332'
  tag fix_id: 'F-72359r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001391']
  tag nist: ['CM-6 b', 'AC-9 (2)']
end
