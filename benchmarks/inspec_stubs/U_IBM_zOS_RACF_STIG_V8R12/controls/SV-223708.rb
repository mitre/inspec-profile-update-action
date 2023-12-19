control 'SV-223708' do
  title 'The IBM RACF WHEN(PROGRAM) SETROPTS value specified must be active.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF Command Shell enter:
SETROPTS LIST

If the WHEN(PROGRAM) value is listed as one of the ATTRIBUTES, this is not a finding.

If the NOWHEN(PROGRAM) value is listed as one of the ATTRIBUTES, this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including the value for the WHEN(PROGRAM) Option. 

WHEN(PROGRAM) is ACTIVATED by issuing the command SETR WHEN(PROGRAM).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25381r514812_chk'
  tag severity: 'medium'
  tag gid: 'V-223708'
  tag rid: 'SV-223708r604139_rule'
  tag stig_id: 'RACF-ES-000610'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25369r514813_fix'
  tag 'documentable'
  tag legacy: ['V-98123', 'SV-107227']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
