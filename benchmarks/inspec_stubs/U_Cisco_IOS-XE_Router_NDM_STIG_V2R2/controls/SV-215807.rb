control 'SV-215807' do
  title 'The Cisco router must be configured to limit the number of concurrent management sessions to an organization-defined number.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to denial-of-service (DoS) attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Note: This requirement is not applicable to file transfer actions such as FTP, SCP and SFTP.

Review the router configuration to determine if concurrent management sessions are limited as shown in the example below:

ip http secure-server 
ip http max-connections 2 
… 
… 
… 
line vty 0 1 
transport input ssh 
line vty 2 4 
transport input none 


If the router is not configured to limit the number of concurrent management sessions, this is a finding.'
  desc 'fix', 'Configure the router to limit the number of concurrent management sessions to an organization-defined number as shown in the example below.

R4(config)#ip http max-connections 2 
R4(config)#line vty 0 1 
R4(config-line)#transport input ssh
R4(config-line)#exit
R4(config)#line vty 2 4 
R4(config-line)# transport input none  
R4(config-line)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17046r648757_chk'
  tag severity: 'medium'
  tag gid: 'V-215807'
  tag rid: 'SV-215807r648759_rule'
  tag stig_id: 'CISC-ND-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-17044r648758_fix'
  tag 'documentable'
  tag legacy: ['SV-105327', 'V-96189']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
