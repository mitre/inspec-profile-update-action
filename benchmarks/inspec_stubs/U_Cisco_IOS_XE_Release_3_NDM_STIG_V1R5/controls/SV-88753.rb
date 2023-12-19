control 'SV-88753' do
  title 'Administrative accounts for device management must be configured on the authentication server and not the Cisco IOS XE router itself (except for the emergency administration account).'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.

Administrative accounts for network device management must be configured on the authentication server and not the network device itself. The only exception is for the emergency administration account (also known as the account of last resort), which is configured locally on each device. Note that more than one emergency administration account may be permitted if approved.'
  desc 'check', 'Verify that administrative accounts are configured on the authentication server.

The configuration should look similar to the example below:

aaa authentication login default radius
radius server RADIUS1
  address ipv4 1.1.1.1
  key <pre-shared key>

If administrative accounts are not configured on the authentication server, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to use multiple authentication servers.

The configuration should look similar to the example below:

aaa authentication login default radius
radius server RADIUS1
  address ipv4 1.1.1.1
  key <pre-shared key>'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74171r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74079'
  tag rid: 'SV-88753r2_rule'
  tag stig_id: 'CISR-ND-000134'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-80619r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
