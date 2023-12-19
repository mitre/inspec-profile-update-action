control 'SV-26071' do
  title 'The system must not process ICMP timestamp requests.'
  desc 'The processing of Internet Control Message Protocol (ICMP) timestamp requests increases the attack surface of the system.'
  desc 'check', 'Determine if the system is configured to respond to ICMP Timestamp requests.  If so, this is a finding.'
  desc 'fix', 'Configure the system to ignore ICMP Timestamp requests.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29247r1_chk'
  tag severity: 'low'
  tag gid: 'V-22409'
  tag rid: 'SV-26071r1_rule'
  tag stig_id: 'GEN003602'
  tag gtitle: 'GEN003602'
  tag fix_id: 'F-26266r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
