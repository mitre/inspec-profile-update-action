control 'SV-253051' do
  title 'The auditd service must be running in TOSS.'
  desc 'Configuring TOSS to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Verify the audit service is enabled and active with the following commands:

$ sudo systemctl is-enabled auditd

enabled

$ sudo systemctl is-active auditd

active

If the service is not "enabled" and "active" this is a finding.'
  desc 'fix', 'Start the auditd service and enable the auditd service with the following commands:

$ sudo systemctl start auditd.service

$ sudo systemctl enable auditd.service'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56504r824823_chk'
  tag severity: 'medium'
  tag gid: 'V-253051'
  tag rid: 'SV-253051r824825_rule'
  tag stig_id: 'TOSS-04-031340'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56454r824824_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
