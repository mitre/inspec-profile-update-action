control 'SV-215854' do
  title 'The Cisco router must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.'
  desc "Centralized management of user accounts and authentication increases the administrative access to the router. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Review the Cisco router configuration to verify that the device is configured to use an authentication server as primary source for authentication as shown in the following example:

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
 login authentication LOGIN_AUTHENTICATION
line vty 0 1
 exec-timeout 10 0
 login authentication LOGIN_AUTHENTICATION

If the Cisco router is not configured to use an authentication server for the purpose of authenticating users prior to granting administrative access, this is a finding.'
  desc 'fix', 'Step 1: Configure the Cisco router to use an authentication server as shown in the following example:

R4(config)#radius host 10.1.48.2 key xxxxxx

Step 2: Configure the authentication order to use the authentication server as primary source for authentication as shown in the following example:

R4(config)#aaa authentication login LOGIN_AUTHENTICATION group radius local

Step 3: Configure all network connections associated with a device management to use an authentication server for the purpose of login authentication.

R4(config)#line vty 0 1
R4(config-line)#login authentication LOGIN_AUTHENTICATION
R4(config-line)#exit
R4(config)#line con 0
R4(config-line)#login authentication LOGIN_AUTHENTICATION
R4(config-line)#exit 
R4(config)#ip http authentication aaa login-authentication LOGIN_AUTHENTICATION'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17093r835126_chk'
  tag severity: 'high'
  tag gid: 'V-215854'
  tag rid: 'SV-215854r835128_rule'
  tag stig_id: 'CISC-ND-001370'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-17091r835127_fix'
  tag 'documentable'
  tag legacy: ['SV-105489', 'V-96351']
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
