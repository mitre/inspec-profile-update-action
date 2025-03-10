control 'SV-223707' do
  title 'The IBM RACF TAPEDSN SETROPTS value specified must be properly set.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF Command Shell enter:
SETROPTS LIST

If the TAPEDSN is enabled then the message "TAPE DATA SET PROTECTION IS ACTIVE" will be displayed, this is not a finding.

NOTE 1: TAPEDSN should be active for domains without a tape management product.

NOTE 2: For domains running CA 1, Computer Associates recommends that TAPEDSN be active and CA 1 parameter OCEOV be set to OFF.

If the TAPEDSN value is set to INACTIVE, this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including the value for the TAPEDSN Option. 

TAPEDSN is ACTIVATED by issuing the command SETR TAPEDSN.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25380r514809_chk'
  tag severity: 'medium'
  tag gid: 'V-223707'
  tag rid: 'SV-223707r604139_rule'
  tag stig_id: 'RACF-ES-000600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25368r514810_fix'
  tag 'documentable'
  tag legacy: ['SV-107225', 'V-98121']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
