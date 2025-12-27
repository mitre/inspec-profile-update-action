control 'SV-41526' do
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
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-285r3_chk'
  tag severity: 'medium'
  tag gid: 'V-782'
  tag rid: 'SV-41526r2_rule'
  tag stig_id: 'GEN006480'
  tag gtitle: 'GEN006480'
  tag fix_id: 'F-936r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECID-1'
  tag cci: ['CCI-001259']
  tag nist: ['SI-4 (1)']
end
