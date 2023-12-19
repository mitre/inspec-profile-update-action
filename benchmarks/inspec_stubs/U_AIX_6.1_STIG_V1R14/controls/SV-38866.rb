control 'SV-38866' do
  title 'The system must not process ICMP timestamp requests.'
  desc 'The processing of Internet Control Message Protocol (ICMP) timestamp requests increases the attack surface of the system.'
  desc 'check', 'Determine if the system is configured to respond to ICMP Timestamp requests. 

#lsfilt

If there is no rule blocking ICMP packet type of 13 and ICMP packet type of 14, this is a finding.'
  desc 'fix', 'Use SMIT or genfilt commands to configure the system firewall to block ICMP packet types 13, and 14.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37859r1_chk'
  tag severity: 'low'
  tag gid: 'V-22409'
  tag rid: 'SV-38866r1_rule'
  tag stig_id: 'GEN003602'
  tag gtitle: 'GEN003602'
  tag fix_id: 'F-32492r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
