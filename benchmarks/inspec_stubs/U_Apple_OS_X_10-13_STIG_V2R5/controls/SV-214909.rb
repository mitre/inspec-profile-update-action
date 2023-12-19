control 'SV-214909' do
  title 'The macOS system must not accept source-routed IPv4 packets.'
  desc "A source-routed packet attempts to specify the network path the packet should take. If the system is not configured to block the incoming source-routed packets, an attacker can redirect the system's network traffic. Configuring the system to drop incoming source-routed IPv4 packets mitigates this risk."
  desc 'check', 'To check if the system is configured to accept "source-routed" packets, run the following command:

sysctl net.inet.ip.accept_sourceroute

If the value is not "0", this is a finding.'
  desc 'fix', 'To configure the system to not accept "source-routed" packets, add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet.ip.accept_sourceroute=0'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16109r397299_chk'
  tag severity: 'medium'
  tag gid: 'V-214909'
  tag rid: 'SV-214909r609363_rule'
  tag stig_id: 'AOSX-13-001195'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16107r397300_fix'
  tag 'documentable'
  tag legacy: ['SV-96411', 'V-81697']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
