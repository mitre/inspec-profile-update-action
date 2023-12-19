control 'SV-215430' do
  title 'AIX must not respond to ICMPv6 echo requests sent to a broadcast address.'
  desc 'Responding to broadcast ICMP echo requests facilitates network mapping and provides a vector for amplification attacks.'
  desc 'check', 'From the command prompt, run the following command:
# /usr/sbin/no -o bcastping 
bcastping = 0

If the value returned is not "0", this is a finding.'
  desc 'fix', 'Configure the system to not respond to IPv6 multicast ICMP ECHO_REQUESTs by running:
# /usr/sbin/no -p -o bcastping=0'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16628r294741_chk'
  tag severity: 'medium'
  tag gid: 'V-215430'
  tag rid: 'SV-215430r508663_rule'
  tag stig_id: 'AIX7-00-003135'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16626r294742_fix'
  tag 'documentable'
  tag legacy: ['SV-101819', 'V-91721']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
