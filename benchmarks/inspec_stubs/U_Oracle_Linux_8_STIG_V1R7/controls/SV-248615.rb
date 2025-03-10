control 'SV-248615' do
  title 'OL 8 must have the rsyslog service enabled and active.'
  desc 'Configuring OL 8 to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements. 
 
Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Verify the rsyslog service is enabled and active with the following commands: 
 
$ sudo systemctl is-enabled rsyslog 
 
enabled 
 
$ sudo systemctl is-active rsyslog 
 
active 
 
If the service is not enabled and active, this is a finding.'
  desc 'fix', 'Start and enable the rsyslog service with the following commands: 
 
$ sudo systemctl start rsyslog.service 
 
$ sudo systemctl enable rsyslog.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52049r779409_chk'
  tag severity: 'medium'
  tag gid: 'V-248615'
  tag rid: 'SV-248615r779411_rule'
  tag stig_id: 'OL08-00-010561'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52003r779410_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
