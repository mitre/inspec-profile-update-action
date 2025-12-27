control 'SV-253878' do
  title 'The Juniper EX switch must be configured to limit the number of concurrent management sessions to 10 or less.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to denial of service (DoS) attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.

Juniper switches apply session limits per access method (e.g., web management, SSH), which means the limit is applicable to local, remote, and root account sessions. Some services, like SSH and NETCONF, also support connection rate-limiting. Connection rate limiting is the number of connections per one minute interval.

Unconfigured management access methods are disabled. For instance, if there is no [edit system services ssh] stanza, that service is unavailable and a connection-limit should not be configured because that will enable the service.'
  desc 'check', 'Review the network device configuration and verify the device limits the number of concurrent management sessions to an organization-defined number for all authorized access methods.

SSH example:
[edit system services ssh]
connection-limit <1..10>;
rate-limit <1..4>;
Note: The SSH connection- and rate-limit directives affect secure file transfer protocols like SCP and SFTP.

NETCONF over SSH example:
[edit system services netconf]
ssh {
    connection-limit <1..10>;
    rate-limit <1..4>;
}
Note: Rate limiting is the permissible number of connections per one minute interval.

If the network device does not limit the number of concurrent management sessions to an organization-defined number, this is a finding.'
  desc 'fix', 'Limit the number of concurrent management sessions to 10.

SSH example:
set system services ssh connection-limit 10
set system services ssh rate-limit <1..4>

NETCONF over SSH example:
set system services netconf ssh connection-limit <1..10>
set system services netconf ssh rate-limit <1..4>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57330r843665_chk'
  tag severity: 'medium'
  tag gid: 'V-253878'
  tag rid: 'SV-253878r879511_rule'
  tag stig_id: 'JUEX-NM-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-57281r843666_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
