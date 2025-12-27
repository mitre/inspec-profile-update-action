control 'SV-45912' do
  title 'The system must have a host-based intrusion detection tool installed.'
  desc 'Without a host-based intrusion detection tool, there is no system-level defense when an intruder gains access to a system or network.  Additionally, a host-based intrusion detection tool can provide methods to immediately lock out detected intrusion attempts.'
  desc 'check', 'Ask the SA or IAO if a host-based intrusion detection application is loaded on the system. The preferred intrusion detection system is McAfee HBSS available through Cybercom.  If another host-based intrusion detection application, such as SELinux, is used on the system, this is not a finding. 

Procedure:
Examine the system to see if the Host Intrusion Prevention System (HIPS) is installed

#rpm -qa | grep MFEhiplsm

If the MFEhiplsm package is installed, HBSS is being used on the system.

If another host-based intrusion detection system is loaded on the system

# find / -name <daemon name> 

Where <daemon name> is the name of the primary application daemon to determine if the application is loaded on the system. 

Determine if the application is active on the system.

Procedure:
# ps -ef | grep <daemon name> 

If no host-based intrusion detection system is installed on the system, this is a finding.'
  desc 'fix', 'Install a host-based intrusion detection tool.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43221r2_chk'
  tag severity: 'medium'
  tag gid: 'V-782'
  tag rid: 'SV-45912r2_rule'
  tag stig_id: 'GEN006480'
  tag gtitle: 'GEN006480'
  tag fix_id: 'F-39291r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001259']
  tag nist: ['SI-4 (1)']
end
