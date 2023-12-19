control 'SV-221693' do
  title 'The Oracle Linux operating system must be configured so that the delay between logon prompts following a failed console logon attempt is at least four seconds.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists verifies compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Verify the operating system enforces a delay of at least four seconds between console logon prompts following a failed logon attempt.

Check the value of the "fail_delay" parameter in the "/etc/login.defs" file with the following command:

# grep -i fail_delay /etc/login.defs
FAIL_DELAY 4

If the value of "FAIL_DELAY" is not set to "4" or greater, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce a delay of at least four seconds between logon prompts following a failed console logon attempt.

Modify the "/etc/login.defs" file to set the "FAIL_DELAY" parameter to "4" or greater:

FAIL_DELAY 4'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23408r419151_chk'
  tag severity: 'medium'
  tag gid: 'V-221693'
  tag rid: 'SV-221693r603260_rule'
  tag stig_id: 'OL07-00-010430'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-23397r419152_fix'
  tag 'documentable'
  tag legacy: ['V-99125', 'SV-108229']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
