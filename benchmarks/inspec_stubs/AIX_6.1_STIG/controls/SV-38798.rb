control 'SV-38798' do
  title 'The system must not respond to ICMP timestamp requests sent to a broadcast address.'
  desc 'The processing of Internet Control Message Protocol (ICMP) timestamp requests increases the attack surface of the system.  Responding to broadcast ICMP timestamp requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', '# /usr/sbin/no -o bcastping
If the value returned is not 0,  this is a finding.'
  desc 'fix', 'Configure the system to ignore ICMP Timestamp requests sent to broadcast addresses.   
#no -po bcastping=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37254r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22411'
  tag rid: 'SV-38798r1_rule'
  tag stig_id: 'GEN003604'
  tag gtitle: 'GEN003604'
  tag fix_id: 'F-32494r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
