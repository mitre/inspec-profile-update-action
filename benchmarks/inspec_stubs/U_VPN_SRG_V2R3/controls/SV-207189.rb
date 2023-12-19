control 'SV-207189' do
  title 'The VPN Gateway must limit the number of concurrent sessions for user accounts to 1 or to an organization-defined number.'
  desc "VPN gateway management includes the ability to control the number of users and user sessions that utilize a VPN gateway. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.

The intent of this policy is to ensure the number of concurrent sessions is deliberately set to a number based on the site's mission and not left unlimited."
  desc 'check', 'Inspect the VPN Gateway configuration. Verify the number of concurrent sessions for user accounts to 1 or to an organization-defined number (defined in the SSP).

If the VPN Gateway does not limit the number of concurrent sessions for user accounts to 1 or to an organization-defined number, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to limit the number of concurrent sessions for user accounts to 1 or to an organization-defined number, as documented in the SSP.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7449r378188_chk'
  tag severity: 'medium'
  tag gid: 'V-207189'
  tag rid: 'SV-207189r608988_rule'
  tag stig_id: 'SRG-NET-000053-VPN-000170'
  tag gtitle: 'SRG-NET-000053'
  tag fix_id: 'F-7449r378189_fix'
  tag 'documentable'
  tag legacy: ['V-97051', 'SV-106189']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
