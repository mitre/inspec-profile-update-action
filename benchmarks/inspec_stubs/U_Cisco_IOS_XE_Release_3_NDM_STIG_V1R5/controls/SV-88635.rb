control 'SV-88635' do
  title 'The Cisco IOS XE router must limit the number of concurrent SSH sessions to an organization-defined number.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Review the Cisco IOS XE router configuration to see if the device limits the number of concurrent SSH sessions to an organization-defined number.

The following commands should be in the configuration:

line vty 0 1
 exec-timeout 60 0
 session-limit 2
 login authentication TEST
 transport input ssh
 transport output ssh
line vty 2 4
 exec-timeout 60 0
 session-limit 2
 login authentication TEST
 transport input none
 transport output none

If the number of concurrent sessions are not limited, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to limit the number of concurrent SSH sessions to an organization-defined number.

The configuration will look similar to the example below:

line vty 0 1
 exec-timeout 60 0
 session-limit 2
 login authentication TEST
 transport input ssh
 transport output ssh
line vty 2 4
 exec-timeout 60 0
 session-limit 2
 login authentication TEST
 transport input none
 transport output none'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74043r3_chk'
  tag severity: 'low'
  tag gid: 'V-73961'
  tag rid: 'SV-88635r2_rule'
  tag stig_id: 'CISR-ND-000001'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-80501r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
