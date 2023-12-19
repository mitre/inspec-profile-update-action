control 'SV-220518' do
  title 'The Cisco switch must be configured to limit the number of concurrent management sessions to an organization-defined number.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Note: This requirement is not applicable to file transfer actions such as FTP, SCP, and SFTP.

Review the switch configuration to determine if concurrent management sessions are limited as show in the example below:

ip http secure-server
ip http max-connections 2
…
…
…

For platforms that support the session-limit command:

line vty 0 4
 session-limit 2
 transport input ssh

For those platforms that do not support the session-limit command, the sessions can also be limited by reducing the number of active vty lines as shown in the example below.

line vty 0 1
 transport input ssh
line vty 2 4
 transport input none

If the switch is not configured to limit the number of concurrent management sessions, this is a finding.'
  desc 'fix', 'Configure the switch to limit the number of concurrent management sessions to an organization-defined number as shown in the example below:

SW4(config)#ip http max-connections 2
SW4(config)#line vty 0 1
SW4(config)#transport input ssh
SW4(config)#line vty 2 4
SW4(config)#transport input none'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22233r835132_chk'
  tag severity: 'medium'
  tag gid: 'V-220518'
  tag rid: 'SV-220518r879511_rule'
  tag stig_id: 'CISC-ND-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-22222r835133_fix'
  tag 'documentable'
  tag legacy: ['SV-110473', 'V-101369']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
