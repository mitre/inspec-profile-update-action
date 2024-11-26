control 'SV-216524' do
  title 'The Cisco router must be configured to enforce the limit of three consecutive invalid logon attempts after which time lock out the user account from accessing the device for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'The Cisco router is not compliant with this requirement. However, the risk associated with this requirement can be fully mitigated if the router is configured to utilize an authentication server to authenticate and authorize users for administrative access.

Review the router configuration to verify that the device is configured to use an authentication server as primary source for authentication as shown in the following example:

radius-server host 10.1.3.16 auth-port 1645 acct-port 1646
 key xxxxxxxxxx
…
…
…
aaa authentication login LOGIN_AUTHENTICATION group radius local
line console
 login authentication LOGIN_AUTHENTICATION
!
line default 
 login authentication LOGIN_AUTHENTICATION
 transport input ssh

If the router is not configured to use an authentication server to authenticate and authorize users for administrative access, this is a finding.'
  desc 'fix', 'Step 1: Configure the router to use an authentication server as shown in the following example:

RP/0/0/CPU0:R3(config)#radius-server host 10.1.3.16 key xxxxxxxx

Step 2: Configure the authentication order to use the authentication server as primary source for authentication as shown in the following example:

RP/0/0/CPU0:R3(config)#aaa authentication login LOGIN_AUTHENTICATION  group radius local

Step 3: Configure all network connections associated with a device management to use an authentication server for the purpose of login authentication as shown in the following example:

RP/0/0/CPU0:R3(config)#line default
RP/0/0/CPU0:R3(config-line)#login authentication LOGIN_AUTHENTICATION
RP/0/0/CPU0:R3(config-line)#exit
RP/0/0/CPU0:R3(config)#line console 
RP/0/0/CPU0:R3(config-line)#login authentication LOGIN_AUTHENTICATION'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17759r288258_chk'
  tag severity: 'medium'
  tag gid: 'V-216524'
  tag rid: 'SV-216524r531088_rule'
  tag stig_id: 'CISC-ND-000150'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-17756r288259_fix'
  tag 'documentable'
  tag legacy: ['SV-105519', 'V-96381']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
