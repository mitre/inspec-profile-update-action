control 'SV-222672' do
  title 'The application must generate audit records when concurrent logons from different workstations occur.'
  desc 'When an application provides users with the ability to concurrently logon, an event must be recorded that indicates the user has logged on from different workstations. It is important to ensure that audit logs differentiate between the two sessions.

The event data must include the user ID, the workstation information and application session information that provides the details necessary to determine which application session executed what action on the system.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify where log records are stored.

Access log records then log on to the application as a regular user from one workstation. Take note of workstation IP address and confirm the address as the source workstation.

Have the application administrator log on to the application from another workstation using the same account.

Validate the IP address of the second workstation is recorded in the logs.

If the application does not create an audit record when concurrent logons occur from different workstations, this is a finding.'
  desc 'fix', 'Configure the application to log concurrent logons from different workstations.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24342r493924_chk'
  tag severity: 'low'
  tag gid: 'V-222672'
  tag rid: 'SV-222672r879877_rule'
  tag stig_id: 'APSC-DV-003360'
  tag gtitle: 'SRG-APP-000506'
  tag fix_id: 'F-24331r493925_fix'
  tag 'documentable'
  tag legacy: ['SV-85045', 'V-70423']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
