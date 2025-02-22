control 'SV-227058' do
  title 'The system must not respond to ICMPv6 echo requests sent to a broadcast address.'
  desc 'Responding to broadcast ICMP echo requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces determine if the system is configured to ignore IPv6 multicast ICMP echo-requests.

Procedure:
# ndd -get /dev/ip ip6_respond_to_echo_multicast

If the result is not 0, this is a finding.'
  desc 'fix', 'Configure the system to not respond to IPv6 multicast ICMP echo-requests.

Procedure:
# ndd -set /dev/ip ip6_respond_to_echo_multicast 0

This command must also be added to a system startup script.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29220r485549_chk'
  tag severity: 'medium'
  tag gid: 'V-227058'
  tag rid: 'SV-227058r603265_rule'
  tag stig_id: 'GEN007950'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29208r485550_fix'
  tag 'documentable'
  tag legacy: ['V-23972', 'SV-29785']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
