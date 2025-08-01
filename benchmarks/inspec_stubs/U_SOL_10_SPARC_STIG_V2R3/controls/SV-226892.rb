control 'SV-226892' do
  title 'The system must not respond to ICMP timestamp requests sent to a broadcast address.'
  desc 'The processing of Internet Control Message Protocol (ICMP) timestamp requests increases the attack surface of the system.  Responding to broadcast ICMP timestamp requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces verify the system does not respond to ICMP timestamp requests set to broadcast addresses.

# ndd /dev/ip ip_respond_to_echo_broadcast

If the result is not 0, this is a finding.'
  desc 'fix', 'Configure the system to not respond to ICMP timestamp requests sent to broadcast addresses.
# ndd -set /dev/ip ip_respond_to_echo_broadcast 0
Also add this command to a system startup script.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29054r484960_chk'
  tag severity: 'medium'
  tag gid: 'V-226892'
  tag rid: 'SV-226892r603265_rule'
  tag stig_id: 'GEN003604'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29042r484961_fix'
  tag 'documentable'
  tag legacy: ['V-22411', 'SV-26624']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
