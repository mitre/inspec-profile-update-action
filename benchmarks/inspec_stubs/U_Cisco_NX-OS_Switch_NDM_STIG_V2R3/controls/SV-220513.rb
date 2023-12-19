control 'SV-220513' do
  title 'The Cisco switch must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.'
  desc "Centralized management of user accounts and authentication increases the administrative access to the switch. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Review the Cisco switch configuration to verify that the device is configured to use an authentication server as primary source for authentication.

Step 1: Verify that an AAA server group is configured for login authentication for both in-band and console access methods.

aaa authentication login default group RADIUS_SERVERS 
aaa authentication login console group RADIUS_SERVERS

Step 2: Verify that an AAA server has been defined for the server group as shown in the example below:

radius-server host 10.1.48.10 key 7 "xxxxxx" authentication accounting 
aaa group server radius RADIUS_SERVERS 
 server 10.1.48.10

If the Cisco switch is not configured to use an authentication server for the purpose of authenticating users prior to granting administrative access, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to use an authentication server as shown in the following example:

Step 1: Define the authentication server. 

SW1(config)# radius-server host 10.1.48.10 key xxxxxx

Step 2: Configure the AAA group.

SW1(config)# aaa group server radius RADIUS_SERVERS
SW1(config-radius)# server 10.1.48.10

Step 3: Use the AAA server for login authentication for both in-band and console access methods.

SW1(config)# aaa authentication login default group RADIUS_SERVERS 
SW1(config)# aaa authentication login console group RADIUS_SERVERS'
  impact 0.7
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22228r539260_chk'
  tag severity: 'high'
  tag gid: 'V-220513'
  tag rid: 'SV-220513r604141_rule'
  tag stig_id: 'CISC-ND-001370'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-22217r539261_fix'
  tag 'documentable'
  tag legacy: ['SV-110675', 'V-101571']
  tag cci: ['CCI-000370', 'CCI-000366']
  tag nist: ['CM-6 (1)', 'CM-6 b']
end
