control 'SV-35026' do
  title 'The system must not respond to Internet Control Message Protocol  (ICMP) timestamp requests sent to a broadcast address.'
  desc 'The processing of ICMP timestamp requests increases the attack surface of the system. Responding to broadcast ICMP timestamp requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'Verify the system does not respond to ICMP timestamp requests set to broadcast addresses.
# ndd -get /dev/ip ip_respond_to_timestamp_broadcast

If the result is greater than 0, this is a finding.'
  desc 'fix', 'Configure the system to not respond to ICMP timestamp requests 
sent to broadcast addresses.
# ndd -set /dev/ip ip_respond_to_timestamp_broadcast 0

Edit /etc/rc.config.d/nddconf and add/set:
TRANSPORT_NAME[x]=ip
NDD_NAME[x]=ip_respond_to_timestamp_broadcast 
NDD_VALUE[x]=0'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36504r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22411'
  tag rid: 'SV-35026r1_rule'
  tag stig_id: 'GEN003604'
  tag gtitle: 'GEN003604'
  tag fix_id: 'F-31861r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
