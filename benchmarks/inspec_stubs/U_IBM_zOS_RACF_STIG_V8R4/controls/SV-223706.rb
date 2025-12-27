control 'SV-223706' do
  title 'The IBM RACF RETPD SETROPTS value specified must be properly set.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF Command Shell enter:
SETROPTS LIST

If the RETPD is enabled then the message "SECURITY RETENTION PERIOD IN EFFECT IS NEVER-EXPIRES DAYS" will be displayed, this is not a finding.

If the RETPD value is not set to "NEVER-EXPIRES", this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including the value for the RETPD (Retention Period) Option. 

RETPD is activated and set to the required value by issuing the command SETR RETPD(99999).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25379r514806_chk'
  tag severity: 'medium'
  tag gid: 'V-223706'
  tag rid: 'SV-223706r604139_rule'
  tag stig_id: 'RACF-ES-000590'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25367r514807_fix'
  tag 'documentable'
  tag legacy: ['SV-107223', 'V-98119']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
