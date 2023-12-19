control 'SV-223705' do
  title 'The IBM RACF GRPLIST SETROPTS value must be set to ACTIVE.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF Command Shell enter:
SETROPTS LIST

If the GRPLIST is enabled then the message "LIST OF GROUPS ACCESS CHECKING IS ACTIVE." will be displayed, this is not a finding.

If the message indicates that LIST OF GROUPS is NOT ACTIVE, this is a finding.'
  desc 'fix', 'Configure the GRPLIST SETROPTS value to be set to ACTIVE. 

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including a status of GRPLIST. 

List of Groups Checking is activated with the command SETR GRPLIST.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25378r514803_chk'
  tag severity: 'medium'
  tag gid: 'V-223705'
  tag rid: 'SV-223705r604139_rule'
  tag stig_id: 'RACF-ES-000580'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25366r514804_fix'
  tag 'documentable'
  tag legacy: ['SV-107221', 'V-98117']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
