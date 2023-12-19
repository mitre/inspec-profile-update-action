control 'SV-38700' do
  title 'The system must provide protection from Internet Control Message Protocol (ICMP) attacks on TCP connections.'
  desc 'The ICMP attacks may be of the form of ICMP source quench attacks and Path MTU Discovery (PMTUD) attacks. If this network option tcp_icmpsecure is turned on, the system does not react to ICMP source quench messages. This will protect against ICMP source quench attacks.  The payload of the ICMP message is tested to determine if the sequence number of the TCP header portion of the payload is within the range of acceptable sequence numbers. This will mitigate PMTUD attacks to a large extent.'
  desc 'check', 'Check the value of the tcp_icmpsecure parameter.

# /usr/sbin/no -o tcp_icmpsecure

If the value returned is not 1, this is a finding.'
  desc 'fix', 'Set the tcp_icmpsecure parameter to 1.
 
# /usr/sbin/no -p -o tcp_icmpsecure=1'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37796r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29496'
  tag rid: 'SV-38700r1_rule'
  tag stig_id: 'GEN000000-AIX0210'
  tag gtitle: 'GEN000000-AIX0210'
  tag fix_id: 'F-33054r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
