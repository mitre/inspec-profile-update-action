control 'SV-38829' do
  title 'The system must not respond to ICMPv6 echo requests sent to a broadcast address.'
  desc 'Responding to broadcast ICMP echo requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', '# /usr/sbin/no -o bcastping
If the value returned is not 0, this is a finding.'
  desc 'fix', 'Configure the system to not respond to IPv6 multicast ICMP ECHO_REQUESTs.
# /usr/sbin/no -p -o bcastping=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23972'
  tag rid: 'SV-38829r1_rule'
  tag stig_id: 'GEN007950'
  tag gtitle: 'GEN007950'
  tag fix_id: 'F-32353r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
