control 'SV-220617' do
  title 'The Cisco switch must be configured to use an authentication server to authenticate users prior to granting administrative access.'
  desc "Centralized management of user accounts and authentication increases the administrative access to the switch. This control is particularly important protection against the insider threat. 

With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Review the Cisco switch configuration to verify that the device is configured to use an authentication server as the primary source for authentication as shown in the example below:

aaa new-model
!
aaa authentication login LOGIN_AUTHENTICATION group radius local
…
…
…
ip http authentication aaa login-authentication LOGIN_AUTHENTICATION
ip http secure-server
…
…
…
radius-server host x.x.x.x auth-port 1645 acct-port 1646 key xxxxxxx
…
…
…
line con 0
 exec-timeout 10 0
 login authentication local radius
line vty 0 1
 exec-timeout 10 0
 login authentication LOGIN_AUTHENTICATION

If the Cisco switch is not configured to use an authentication server to authenticate users prior to granting administrative access, this is a finding.'
  desc 'fix', 'Step 1: Configure the Cisco switch to use an authentication server as shown in the example below:

SW4(config)#radius host 10.1.48.2 key xxxxxx

Step 2: Configure the authentication order to use the authentication server as the primary source for authentication as shown in the example below:

SW4(config)#aaa authentication login LOGIN_AUTHENTICATION group radius local

Step 3: Configure all network connections associated with device management to use an authentication server for login authentication:

SW4(config)#line vty 0 1
SW4(config-line)#login authentication LOGIN_AUTHENTICATION
SW4(config-line)#exit
SW4(config)#line con 0
SW4(config-line)#login authentication local radius
SW4(config-line)#exit 
SW4(config)#ip http authentication aaa login-authentication LOGIN_AUTHENTICATION'
  impact 0.7
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22332r892389_chk'
  tag severity: 'high'
  tag gid: 'V-220617'
  tag rid: 'SV-220617r892391_rule'
  tag stig_id: 'CISC-ND-001370'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-22321r892390_fix'
  tag 'documentable'
  tag legacy: ['SV-110463', 'V-101359']
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
