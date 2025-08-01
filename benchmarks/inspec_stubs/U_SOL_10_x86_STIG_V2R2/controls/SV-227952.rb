control 'SV-227952' do
  title 'The system must have a host-based intrusion detection tool installed.'
  desc 'Without a host-based intrusion detection tool, there is no system-level defense when an intruder gains access to a system or network.  Additionally, a host-based intrusion detection tool can provide methods to immediately lock out detected intrusion attempts.'
  desc 'check', 'Ask the SA or IAO if a host-based intrusion detection application is loaded on the system.

Determine if the application is loaded on the system.

Procedure:
# find / -name <daemon name> -print 

 

Determine if the application is active on the system.

Procedure:
# ps -ef | grep <daemon name> 

If no host-based intrusion detection system is installed on the system, this is a finding.'
  desc 'fix', 'Install a host-based intrusion detection tool.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30114r490276_chk'
  tag severity: 'medium'
  tag gid: 'V-227952'
  tag rid: 'SV-227952r603266_rule'
  tag stig_id: 'GEN006480'
  tag gtitle: 'SRG-OS-000191'
  tag fix_id: 'F-30102r490277_fix'
  tag 'documentable'
  tag legacy: ['V-782', 'SV-41526']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
