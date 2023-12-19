control 'SV-29288' do
  title 'The system must not respond to Internet Control Message Protocol (ICMP) timestamp requests sent to a broadcast address.'
  desc 'The processing of (ICMP) timestamp requests increases the attack surface of the system.  Responding to broadcast ICMP timestamp requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'fix', 'Configure the system to not respond to ICMP TIMESTAMP_REQUESTs sent to broadcast addresses. Edit /etc/sysctl.conf and add a setting for "net.ipv4.icmp_echo_ignore_broadcasts=1" and reload the sysctls.

Procedure:
# echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22411'
  tag rid: 'SV-29288r1_rule'
  tag stig_id: 'GEN003604'
  tag gtitle: 'GEN003604'
  tag fix_id: 'F-31645r1_fix'
  tag 'documentable'
  tag mitigations: 'GEN000000-FW'
  tag mitigation_control: "The system's firewall default-deny policy mitigates the risk from this vulnerability."
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
