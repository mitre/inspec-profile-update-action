control 'SV-216544' do
  title 'The Cisco router must be configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access.'
  desc "Centralized management of user accounts and authentication increases the administrative access to the router. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Review the Cisco router configuration to verify that the device is configured to use at least two authentication servers as primary source for authentication as shown in the following example:

radius-server host 10.1.3.16 auth-port 1645 acct-port 1646
 key xxxxxxxxxx
radius-server host 10.1.3.17 auth-port 1645 acct-port 1646
 key xxxxxxxxxx…
…
…
aaa authentication login LOGIN_AUTHENTICATION group radius local
line console
 login authentication LOGIN_AUTHENTICATION
!
line default 
 login authentication LOGIN_AUTHENTICATION
 transport input ssh

If the Cisco router is not configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access, this is a finding.'
  desc 'fix', 'Step 1: Configure the router to use at least two authentication servers as shown in the following example:

RP/0/0/CPU0:R3(config)#radius-server host 10.1.3.16 key xxxxxxxx
RP/0/0/CPU0:R3(config)#radius-server host 10.1.3.17 key xxxxxxxx

Step 2: Configure the authentication order to use the authentication servers as primary source for authentication as shown in the following example:

RP/0/0/CPU0:R3(config)#aaa authentication login LOGIN_AUTHENTICATION  group radius local

Step 3: Configure all network connections associated with a device management to use the authentication servers for the purpose of login authentication as shown in the following example:

RP/0/0/CPU0:R3(config)#line default
RP/0/0/CPU0:R3(config-line)#login authentication LOGIN_AUTHENTICATION
RP/0/0/CPU0:R3(config-line)#exit
RP/0/0/CPU0:R3(config)#line console 
RP/0/0/CPU0:R3(config-line)#login authentication LOGIN_AUTHENTICATION'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17779r916073_chk'
  tag severity: 'high'
  tag gid: 'V-216544'
  tag rid: 'SV-216544r916111_rule'
  tag stig_id: 'CISC-ND-001370'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-17776r916074_fix'
  tag 'documentable'
  tag legacy: ['SV-105621', 'V-96483']
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
