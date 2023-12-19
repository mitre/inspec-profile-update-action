control 'SV-35038' do
  title 'The system must not send IPv4 ICMP redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table possibly revealing portions of the network topology."
  desc 'check', 'Verify the system does not send IPv4 ICMP redirect messages.
# ndd -get /dev/ip ip_send_redirects

If the return value/result is not 0, this is a finding.'
  desc 'fix', 'Configure the system to not send IPv4 ICMP redirect messages.
# ndd -set /dev/ip ip_send_redirects 0

Edit /etc/rc.config.d/nddconf and add/set:
TRANSPORT_NAME[x]=ip
NDD_NAME[x]=ip_send_redirects
NDD_VALUE[x]=0'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36507r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22417'
  tag rid: 'SV-35038r1_rule'
  tag stig_id: 'GEN003610'
  tag gtitle: 'GEN003610'
  tag fix_id: 'F-31865r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
