control 'SV-253927' do
  title 'The Juniper EX switch must be configured to prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'Some authentication implementations can be configured to use cached authenticators.

If cached authentication information is out-of-date, the validity of the authentication information may be questionable.

The organization-defined time period should be established for each device depending on the nature of the device; for example, a device with just a few administrators in a facility with spotty network connectivity may merit a longer caching time period than a device with many administrators.'
  desc 'check', 'Review the network device configuration to determine if the network device or its associated authentication server prohibits the use of cached authenticators after an organization-defined time period.

Verify idle-timeouts, SSH keepalive messages, and SSH rekey are configured to meet the requirements of the target network.
[edit system]
login {
    idle-timeout 10;
}
system {
    services {
        ssh {
            protocol-version v2;
            client-alive-count-max (0..255);
            client-alive-interval (0..65535 seconds);
            rekey {
                data-limit (51200..4294967295 bytes);
                time-limit (1..1440 minutes);
            }
        }
    }
}

For externally authenticated accounts, verify the external authentication server enforces appropriate authenticator timeouts.

If cached authenticators are used after an organization-defined time period, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to prohibit the use of cached authenticators after an organization-defined time period.

set system login idle-timeout 10

set system services ssh protocol-version v2
set system services ssh client-alive-count-max (0..255)
set system services ssh client-alive-interval (0..65535 seconds)
set system services ssh rekey data-limit (51200..4294967295 bytes)
set system services ssh rekey time-limit (1..1440 minutes)'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57379r843812_chk'
  tag severity: 'medium'
  tag gid: 'V-253927'
  tag rid: 'SV-253927r843814_rule'
  tag stig_id: 'JUEX-NM-000500'
  tag gtitle: 'SRG-APP-000400-NDM-000313'
  tag fix_id: 'F-57330r843813_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
