control 'SV-214915' do
  title 'The macOS system must prevent local applications from generating source-routed packets.'
  desc "A source-routed packet attempts to specify the network path that the system should take. If the system is not configured to block the sending of source-routed packets, an attacker can redirect the system's network traffic."
  desc 'check', 'To check if the system is configured to forward source-routed packets, run the following command:

sysctl net.inet.ip.sourceroute

If the value is not set to "0", this is a finding.'
  desc 'fix', 'To configure the system to not forward source-routed packets, add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet.ip.sourceroute=0'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16115r397317_chk'
  tag severity: 'medium'
  tag gid: 'V-214915'
  tag rid: 'SV-214915r609363_rule'
  tag stig_id: 'AOSX-13-001215'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16113r397318_fix'
  tag 'documentable'
  tag legacy: ['SV-96425', 'V-81711']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
