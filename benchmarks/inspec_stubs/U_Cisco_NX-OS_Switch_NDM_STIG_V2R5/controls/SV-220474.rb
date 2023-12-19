control 'SV-220474' do
  title 'The Cisco switch must be configured to limit the number of concurrent management sessions to an organization-defined number.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Review the switch configuration to determine if concurrent management sessions are limited as show in the example below:

line vty 
 session-limit 2

If the switch is not configured to limit the number of concurrent management sessions, this is a finding.'
  desc 'fix', 'Configure the switch to limit the number of concurrent management sessions to an organization-defined number as shown in the example below:

SW4(config)# line vty 
SW4(config)# session-limit 2'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22189r539143_chk'
  tag severity: 'medium'
  tag gid: 'V-220474'
  tag rid: 'SV-220474r879511_rule'
  tag stig_id: 'CISC-ND-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-22178r539144_fix'
  tag 'documentable'
  tag legacy: ['SV-110595', 'V-101491']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
