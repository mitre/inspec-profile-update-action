control 'SV-81033' do
  title 'The Juniper SRX Services Gateway must limit the number of sessions per minute to an organization-defined number for SSH to protect remote access management from unauthorized access.'
  desc "The rate-limit command limits the number of SSH session attempts allowed per minute which helps limit an attacker's ability to perform DoS attacks. The rate limit should be as restrictive as operationally practical.

Juniper Networks recommends a best practice of 4 for the rate limit, however the limit should be as restrictive as operationally practical. 

User connections that exceed the rate-limit will be closed immediately after the connection is initiated. They will not be in a waiting state."
  desc 'check', 'Verify the Juniper SRX sets a connection-limit for the SSH protocol.

Show system services ssh

If the SSH connection-limit is not set to 4 or an organization-defined value, this is a finding.'
  desc 'fix', 'Configure the SSH protocol with a rate limit.

[edit]
set system services ssh rate-limit 4

Note: Juniper Networks recommends a best practice of 4 for the rate limit; however, the limit should be as restrictive as operationally practical.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67189r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66543'
  tag rid: 'SV-81033r1_rule'
  tag stig_id: 'JUSX-DM-000163'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-72619r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
