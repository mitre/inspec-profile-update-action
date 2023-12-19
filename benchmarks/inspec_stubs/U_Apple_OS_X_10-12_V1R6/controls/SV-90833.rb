control 'SV-90833' do
  title 'The OS X system must prevent local applications from generating source-routed packets.'
  desc "A source-routed packet attempts to specify the network path that the system should take. If the system is not configured to block the sending of source-routed packets, an attacker can redirect the system's network traffic."
  desc 'check', 'To check if the system is configured to forward source-routed packets, run the following command:

sysctl net.inet.ip.sourceroute

If the value is not set to "0", this is a finding.'
  desc 'fix', 'To configure the system to not forward source-routed packets, add the following line to "/etc/sysctl.conf", creating the file if necessary:

net.inet.ip.sourceroute=0'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75831r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76145'
  tag rid: 'SV-90833r1_rule'
  tag stig_id: 'AOSX-12-001215'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82783r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
