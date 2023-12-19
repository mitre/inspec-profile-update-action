control 'SV-253920' do
  title 'The Juniper EX switch must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: A time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Determine if the network device is configured to synchronize internal information system clocks with the primary and secondary time sources.

Verify the Network Time Protocol (NTP) configuration.
[edit system ntp]
authentication-key 1 type sha256 value "PSK"; ## SECRET-DATA
authentication-key 2 type sha1 value "PSK"; ## SECRET-DATA
server <address 1> key 1 prefer; ## SECRET-DATA
server <address 2> key 2; ## SECRET-DATA
trusted-key [ 1 2 ];
source-address <lo0 or OOBM address>;

If the network device is not configured to  synchronize internal information system clocks with the primary and secondary time sources, this is a finding.'
  desc 'fix', 'Configure the network device to synchronize internal information system clocks with the primary and secondary time sources.

set system ntp authentication-key 1 type sha256
set system ntp authentication-key 1 value "PSK"
set system ntp authentication-key 2 type sha1
set system ntp authentication-key 2 value "PSK"
set system ntp server <address 1> key 1
set system ntp server <address 1> prefer
set system ntp server <address 2> key 2
set system ntp trusted-key 1
set system ntp trusted-key 2
set system ntp source-address <lo0 or OOBM address>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57372r843791_chk'
  tag severity: 'medium'
  tag gid: 'V-253920'
  tag rid: 'SV-253920r843793_rule'
  tag stig_id: 'JUEX-NM-000430'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-57323r843792_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
