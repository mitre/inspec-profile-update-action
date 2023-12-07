control 'SV-38797' do
  title 'The system must not respond to ICMPv4 echoes sent to a broadcast address.'
  desc 'Responding to broadcast Internet Control Message Protocol (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', '# /usr/sbin/no -o bcastping
If the value returned is not 0,  this is a finding.'
  desc 'fix', 'Configure the system to ignore ICMP ECHO_REQUESTs sent to broadcast addresses. 

# no -po bcastping=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37253r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22410'
  tag rid: 'SV-38797r1_rule'
  tag stig_id: 'GEN003603'
  tag gtitle: 'GEN003603'
  tag fix_id: 'F-32493r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
