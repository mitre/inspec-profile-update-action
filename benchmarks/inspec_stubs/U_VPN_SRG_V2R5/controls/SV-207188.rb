control 'SV-207188' do
  title 'The VPN Gateway must notify the user, upon successful logon (access), of the number of unsuccessful logon (access) attempts since the last successful logon (access).'
  desc 'Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the number of unsuccessful attempts that were made to login to their account allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.

This applies to gateways that have the concept of a user account and have the login function residing on the gateway or the gateway acts as a user intermediary.'
  desc 'check', 'Determine if the VPN Gateway is either configured to notify the administrator of the number of unsuccessful login attempts since the last successful login or configured to use an authentication server which would perform this function. If the administrator is not notified of the number of unsuccessful login attempts since the last successful login, this is a finding.

If the VPN Gateway does not notify the user, upon successful logon (access), of the number of unsuccessful logon (access) attempts since the last successful logon (access), this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to notify the user, upon successful logon (access), of the number of unsuccessful logon (access) attempts since the last successful logon (access).'
  impact 0.3
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7448r378185_chk'
  tag severity: 'low'
  tag gid: 'V-207188'
  tag rid: 'SV-207188r608988_rule'
  tag stig_id: 'SRG-NET-000049-VPN-000150'
  tag gtitle: 'SRG-NET-000049'
  tag fix_id: 'F-7448r378186_fix'
  tag 'documentable'
  tag legacy: ['V-97049', 'SV-106187']
  tag cci: ['CCI-000053']
  tag nist: ['AC-9 (1)']
end
