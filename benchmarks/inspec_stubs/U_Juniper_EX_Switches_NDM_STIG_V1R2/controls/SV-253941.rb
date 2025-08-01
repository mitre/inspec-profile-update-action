control 'SV-253941' do
  title 'The Juniper EX switch must be configured to use an authentication server for the purpose of authenticating users prior to granting administrative access.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Review the network device configuration to verify the device is configured to use an authentication server as the primary source for authentication. Verify the RADIUS and/or TACACS+ server addresses.

[edit system]
radius-server {
    <RADIUS-1 address> secret "hashed PSK"; ## SECRET-DATA
    <RADIUS-2 address> secret "hashed PSK"; ## SECRET-DATA
}
tacplus-server {
    <TACPLUS-1 address> secret "hashed PSK"; ## SECRET-DATA
    <TACPLUS-2 address> secret "hashed PSK"; ## SECRET-DATA
}

Verify the authentication order places the external authentication server first.
[edit system]
authentication-order [ radius tacplus password ];

Note: Only the global authentication order is required; all administrative access methods will honor the global setting unless configured separately. 

If the network device is not configured to use an authentication server to authenticate users prior to granting administrative access, this is a finding.'
  desc 'fix', 'Configure the network device to use an authentication server.
set system radius-server <RADIUS-1 address> secret "<PSK>"
set system tacplus-server <TACPLUS-1 address> secret "<PSK>"

Configure the authentication order to use the authentication server as primary source for authentication.
set system authentication-order radius
set system authentication-order tacplus
set system authentication-order password'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57393r843854_chk'
  tag severity: 'high'
  tag gid: 'V-253941'
  tag rid: 'SV-253941r843856_rule'
  tag stig_id: 'JUEX-NM-000640'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-57344r843855_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
