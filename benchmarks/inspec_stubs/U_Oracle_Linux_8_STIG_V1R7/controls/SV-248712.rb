control 'SV-248712' do
  title 'OL 8 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists verifies compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements. 
 
Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Verify the operating system enforces a delay of at least four seconds between console logon prompts following a failed logon attempt with the following command: 
 
$ sudo grep -i fail_delay /etc/login.defs 
 
FAIL_DELAY 4 
 
If the value of "FAIL_DELAY" is not set to "4" or greater or the line is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to enforce a delay of at least four seconds between logon prompts following a failed console logon attempt. 
 
Modify the "/etc/login.defs" file to set the "FAIL_DELAY" parameter to "4" or greater: 
 
FAIL_DELAY 4'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52146r779700_chk'
  tag severity: 'medium'
  tag gid: 'V-248712'
  tag rid: 'SV-248712r779702_rule'
  tag stig_id: 'OL08-00-020310'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-52100r779701_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
