control 'SV-35025' do
  title 'The system must not respond to ICMPv4 echoes sent to a broadcast address.'
  desc 'Responding to broadcast Internet Control Message Protocol (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.'
  desc 'fix', 'Configure the system to not respond to ICMP ECHO_REQUESTs 
sent to broadcast addresses.

# ndd -set /dev/ip ip_respond_to_echo_broadcast 0

Edit /etc/rc.config.d/nddconf and add/set:
TRANSPORT_NAME[x]=ip
NDD_NAME[x]=ip_respond_to_echo_broadcast
NDD_VALUE[x]=0'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22410'
  tag rid: 'SV-35025r1_rule'
  tag stig_id: 'GEN003603'
  tag gtitle: 'GEN003603'
  tag fix_id: 'F-31860r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
