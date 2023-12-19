control 'SV-26073' do
  title 'The system must not respond to ICMPv4 echoes sent to a broadcast address.'
  desc 'Responding to broadcast Internet Control Message Protocol (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Determine if the system is configured to respond to ICMP ECHO_REQUESTs sent to broadcast addresses.  If so, this is a finding.'
  desc 'fix', 'Configure the system to ignore ICMP ECHO_REQUESTs sent to broadcast addresses.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29248r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22410'
  tag rid: 'SV-26073r1_rule'
  tag stig_id: 'GEN003603'
  tag gtitle: 'GEN003603'
  tag fix_id: 'F-26267r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
