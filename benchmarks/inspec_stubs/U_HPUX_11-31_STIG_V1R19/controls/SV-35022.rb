control 'SV-35022' do
  title 'The system must not process Internet Control Message Protocol  (ICMP) timestamp requests.'
  desc 'The processing of ICMP timestamp requests increases the attack surface of the system.'
  desc 'check', 'Verify the system does not respond to ICMP Timestamp requests.
# ndd -get /dev/ip ip_respond_to_timestamp

If the result is not 0, this is a finding.'
  desc 'fix', 'Disable ICMP Timestamp responses on the system.
# ndd -set /dev/ip ip_respond_to_timestamp 0

Edit /etc/rc.config.d/nddconf and add/set:
TRANSPORT_NAME[x]=ip
NDD_NAME[x]=ip_respond_to_timestamp
NDD_VALUE[x]=0'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36502r1_chk'
  tag severity: 'low'
  tag gid: 'V-22409'
  tag rid: 'SV-35022r1_rule'
  tag stig_id: 'GEN003602'
  tag gtitle: 'GEN003602'
  tag fix_id: 'F-31859r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
