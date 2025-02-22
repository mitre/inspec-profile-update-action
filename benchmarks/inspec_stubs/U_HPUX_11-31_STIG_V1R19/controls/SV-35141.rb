control 'SV-35141' do
  title 'The system must have a host-based intrusion detection tool installed.'
  desc 'Without a host-based intrusion detection tool, there is no system-level defense when an intruder gains access to a system or network.  Additionally, a host-based intrusion detection tool can provide methods to immediately lock out detected intrusion attempts.'
  desc 'check', 'A few applications providing host-based network intrusion protection are:

- Dragon Squire by Enterasys Networks
- ITA by Symantec
- Hostsentry by Psionic Software
- Logcheck by Psionic Software
- RealSecure agent by ISS
- Swatch by Stanford University

Ask the SA or IAO if a host-based intrusion detection application is loaded on the system (where <daemon name> is the name of the primary application daemon) to determine if the application is loaded on the system.

# find / -name <daemon> | xargs -n1 ls -lL 

Determine if the application is active on the system.
# ps -ef | grep <daemon name> 

If no host-based intrusion detection system is installed on the system, this is a finding.'
  desc 'fix', 'Install a host-based intrusion detection tool.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34998r1_chk'
  tag severity: 'medium'
  tag gid: 'V-782'
  tag rid: 'SV-35141r1_rule'
  tag stig_id: 'GEN006480'
  tag gtitle: 'GEN006480'
  tag fix_id: 'F-32105r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECID-1'
  tag cci: ['CCI-001259']
  tag nist: ['SI-4 (1)']
end
