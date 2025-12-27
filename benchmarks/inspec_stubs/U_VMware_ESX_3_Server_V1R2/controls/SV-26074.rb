control 'SV-26074' do
  title 'The system must not respond to ICMP timestamp requests sent to a broadcast address.'
  desc 'The processing of Internet Control Message Protocol (ICMP) timestamp requests increases the attack surface of the system.  Responding to broadcast ICMP timestamp requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Determine if the system is configured to respond to ICMP Timestamp requests sent to broadcast addresses.  If so, this is a finding.'
  desc 'fix', 'Configure the system to ignore ICMP Timestamp requests sent to broadcast addresses.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29249r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22411'
  tag rid: 'SV-26074r1_rule'
  tag stig_id: 'GEN003604'
  tag gtitle: 'GEN003604'
  tag fix_id: 'F-26268r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
