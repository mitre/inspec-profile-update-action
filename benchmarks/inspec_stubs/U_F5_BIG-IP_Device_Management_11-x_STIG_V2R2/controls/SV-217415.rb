control 'SV-217415' do
  title 'The BIG-IP appliance must be configured to enforce access restrictions associated with changes to device configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to device configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the device can potentially have significant effects on the overall security of the device. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to device components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Verify the BIG-IP appliance is configured to enforce access restrictions associated with changes to device configuration. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server that assigns authenticated users to an appropriate group.

Navigate to System >> Users >> Remote Role Groups.

Verify Remote Role Groups are assigned proper Role Access and Partition Access to enforce access restrictions associated with changes to device configuration.

If the BIG-IP appliance is not configured to enforce such access restrictions, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use role-based access to enforce access restrictions associated with changes to device configuration.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18640r290799_chk'
  tag severity: 'medium'
  tag gid: 'V-217415'
  tag rid: 'SV-217415r879753_rule'
  tag stig_id: 'F5BI-DM-000213'
  tag gtitle: 'SRG-APP-000380-NDM-000304'
  tag fix_id: 'F-18638r290800_fix'
  tag 'documentable'
  tag legacy: ['SV-74639', 'V-60209']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
