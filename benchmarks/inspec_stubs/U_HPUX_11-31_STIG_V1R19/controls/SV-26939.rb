control 'SV-26939' do
  title 'The system must not send IPv6 ICMP redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts of a more direct route existing for a particular destination. These messages contain information from the system's route table possibly revealing portions of the network topology."
  desc 'check', 'Determine if the system is configured to not send IPv6 ICMP redirect messages. 
# ndd -get /dev/ip6 ip6_send_redirects

If the command returns 1, this is a finding.'
  desc 'fix', 'Configure the system to not send IPv6 ICMP redirect messages.   
# ndd -set /dev/ip6 ip6_send_redirects 0

Edit /etc/rc.config.d/nddconf:

TRANSPORT_NAME[index]=ip6
NDD_NAME[index]=ip6_send_redirects 
NDD_VALUE[index]=0

Where:
      index is the next available integer value of the nddconf file.
      n is a number: either 1 to turn the feature ON or 0 to turn it OFF.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-27887r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22551'
  tag rid: 'SV-26939r1_rule'
  tag stig_id: 'GEN007880'
  tag gtitle: 'GEN007880'
  tag fix_id: 'F-24184r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
