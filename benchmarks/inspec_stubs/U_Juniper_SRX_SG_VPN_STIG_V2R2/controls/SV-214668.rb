control 'SV-214668' do
  title 'The Juniper SRX Services Gateway VPN must limit the number of concurrent sessions for user accounts to one (1) and administrative accounts to three (3), or set to an organization-defined number.'
  desc "Network element management includes the ability to control the number of users and user sessions that utilize a network element. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.

The intent of this policy is to ensure the number of concurrent sessions is deliberately set to a number based on the site's mission and not left unlimited."
  desc 'check', 'Verify the VPN Internet Key Exchange (IKE) gateway limits concurrent sessions.

[edit]
show security ike

View the value for the connections-limit.

If the VPN IKE gateway does not limit the number of concurrent sessions for user accounts to one (1) and administrative accounts to three (3), or is set to an organization-defined number, this is a finding.'
  desc 'fix', 'Configure the VPN IKE gateway to limit concurrent sessions. The following is an example.

[edit]
set security ike gateway <VPN-GATEWAY> dynamic connections-limit 1

[edit]
set security ike gateway <VPN-GATEWAY> dynamic connections-limit 3'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15869r297591_chk'
  tag severity: 'medium'
  tag gid: 'V-214668'
  tag rid: 'SV-214668r382774_rule'
  tag stig_id: 'JUSX-VN-000001'
  tag gtitle: 'SRG-NET-000053'
  tag fix_id: 'F-15867r297592_fix'
  tag 'documentable'
  tag legacy: ['SV-81119', 'V-66629']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
