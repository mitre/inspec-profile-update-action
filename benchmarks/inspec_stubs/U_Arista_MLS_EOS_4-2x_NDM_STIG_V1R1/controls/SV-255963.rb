control 'SV-255963' do
  title 'The network device must be configured to use an authentication server to authenticate users prior to granting administrative access.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Verify the Arista network device is configured to use an authentication server as primary source for authentication.

Verify the Arista network device configuration for RADIUS server IP, aaa group server, and defined encryption key using the following example command:

switch#show running-config |section radius
radius-server host 192.168.10.101 key 7 106D1A182224E12AZ
!
aaa group server radius RADIUS_1
   server 192.168.10.101
!
switch#show running-config | section aaa
aaa authentication login default group radius local
aaa authentication login console group radius local
aaa authentication dot1x default group radius
aaa authentication policy on-success log
aaa authentication policy on-failure log
aaa authorization console
aaa authorization commands all default local
aaa accounting exec default start-stop group radius logging
aaa accounting system default start-stop group radius logging
aaa accounting commands all default start-stop logging group radius

If the Arista network device is not configured to use an authentication server to authenticate users prior to granting administrative access, this is a finding.'
  desc 'fix', 'Configure the Arista network device to use an authentication server.

Step 1: Configure the Arista network device to use RADIUS server using the following commands:

switch#config
switch(config)#radius-server host 192.168.10.101 key 7 106D1A182224E12AZ
aaa group server radius RADIUS_1
   server 192.168.10.101

Step 2: Configure all network connections associated with device management to use an authentication server for login authentication.

switch(config)#aaa authentication login default group radius local
aaa authentication login console group radius local
aaa authentication dot1x default group radius
aaa authentication policy on-success log
aaa authentication policy on-failure log
aaa authorization console
aaa authorization commands all default local
aaa accounting exec default start-stop group radius logging
aaa accounting system default start-stop group radius logging
aaa accounting commands all default start-stop logging group radius
switch(config)#exit'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59639r882229_chk'
  tag severity: 'high'
  tag gid: 'V-255963'
  tag rid: 'SV-255963r882231_rule'
  tag stig_id: 'ARST-ND-000810'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-59582r882230_fix'
  tag 'documentable'
  tag cci: ['CCI-000370']
  tag nist: ['CM-6 (1)']
end
