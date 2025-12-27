control 'SV-80991' do
  title 'The Juniper SRX Services Gateway must authenticate NTP servers before establishing a network connection using bidirectional authentication that is cryptographically based.'
  desc '<0> [object Object]'
  desc 'check', 'Verify the Juniper SRX is configured to synchronize internal information system clocks with the primary and secondary NTP sources.

[edit]
show system ntp

If the NTP configuration is not configured to use authentication, this is a finding.'
  desc 'fix', 'The Juniper SRX can only be configured to use MD5 authentication keys. This algorithm is not FIPS 140-2 validated; therefore, it violates CCI-000803, which is a CAT 1. However, MD5 is preferred to no authentication at all. The following commands configure the Juniper SRX to use MD5 authentication keys. 

set system ntp authentication-key 1 type md5
set system ntp authentication-key 1 value "$9$EgfcrvX7VY4ZEcwgoHjkP5REyv87"
set system ntp authentication-key 2 type md5
set system ntp authentication-key 2 value "kP5$EgvVfcrwgoY4X7ZEcH$9j RExz50"
set system ntp server <NTP_server_IP> key 1
set system ntp server <NTP_server_IP> prefer
set system ntp server <NTP_server_IP> key 2
set system ntp trusted-key 1
set system ntp trusted-key 2'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67147r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66501'
  tag rid: 'SV-80991r1_rule'
  tag stig_id: 'JUSX-DM-000110'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-72577r1_fix'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
