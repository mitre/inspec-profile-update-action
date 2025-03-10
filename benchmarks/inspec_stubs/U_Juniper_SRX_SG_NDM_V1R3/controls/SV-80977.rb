control 'SV-80977' do
  title 'The Juniper SRX Services Gateway must be configured to synchronize internal information system clocks with the primary and secondary NTP servers for the network.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on log events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources.'
  desc 'check', 'Verify the Juniper SRX is configured to synchronize internal information system clocks with the primary and secondary NTP sources.

[edit]
show system ntp

If the Juniper SRX is not configured to synchronize internal information system clocks with an NTP server, this is a finding.'
  desc 'fix', 'The following commands allow the device to keep time synchronized with the network. To designate a primary NTP server, add the “prefer” keyword to the server statement.

[edit]
set system ntp server <NTP-server1-IP> prefer
set system ntp source-address <MGT-IP-Address>
set system ntp server <NTP-server2-IP>
set system ntp source-address <MGT-IP-Address>'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66487'
  tag rid: 'SV-80977r1_rule'
  tag stig_id: 'JUSX-DM-000094'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-72563r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
