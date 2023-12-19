control 'SV-227796' do
  title 'The system must not respond to ICMPv4 echoes sent to a broadcast address.'
  desc 'Responding to broadcast Internet Control Message Protocol (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces verify the system does not respond to ICMP ECHO_REQUESTs set to broadcast addresses.
# ndd /dev/ip ip_respond_to_echo_broadcast

If the result is not 0, this is a finding.'
  desc 'fix', 'Configure the system to not respond to ICMP ECHO_REQUESTs sent to broadcast addresses.
# ndd -set /dev/ip ip_respond_to_echo_broadcast 0
Also add this command to a system startup script.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29958r489742_chk'
  tag severity: 'medium'
  tag gid: 'V-227796'
  tag rid: 'SV-227796r603266_rule'
  tag stig_id: 'GEN003603'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29946r489743_fix'
  tag 'documentable'
  tag legacy: ['V-22410', 'SV-26622']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
