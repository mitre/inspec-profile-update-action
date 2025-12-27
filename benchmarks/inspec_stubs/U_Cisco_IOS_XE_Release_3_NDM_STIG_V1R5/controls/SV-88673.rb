control 'SV-88673' do
  title 'The Cisco IOS XE router must generate audit records containing information that establishes the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., administrators or processes acting on behalf of administrators) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.

Event identifiers (if authenticated or otherwise known) include, but are not limited to, user database tables, primary key values, user names, or process identifiers.'
  desc 'check', 'Verify that logging of user information is configured on the Cisco IOS XE router.

The configuration will look similar to the example below:

logging userinfo

If logging of user information is not configured, this is a finding.'
  desc 'fix', 'Enter the following commands to enable logging of user information:  

logging userinfo'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74081r3_chk'
  tag severity: 'low'
  tag gid: 'V-73999'
  tag rid: 'SV-88673r2_rule'
  tag stig_id: 'CISR-ND-000032'
  tag gtitle: 'SRG-APP-000100-NDM-000230'
  tag fix_id: 'F-80539r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
