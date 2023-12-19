control 'SV-223704' do
  title 'The IBM RACF PROTECTALL SETROPTS value specified must be properly set.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF Command Shell enter:
SETROPTS LIST

If the SETROPTS values for PROTECTALL is ACTIVE and set to FAIL, this is not a finding.

If the SETROPTS PROTECTALL parameter is set to NOPROTECTALL or PROTECTALL(WARNING), this is a finding.

Additional analysis may be required to determine whether this finding should be downgraded to a Category II or remain a Category I.

Example of a Category I finding where not a further analysis is required:

Control Options: SETROPTS NOPROTECTALL

Example of a possible Category I finding requiring additional analysis:

Control Options: SETROPTS PROTECTALL(WARNING)

PROTECTALL(WARNING) allows access to a data set only if it is not at protected by a profile in the DATASET resource class. Therefore if all sensitive data sets are properly protected by profiles in the DATASET resource class, PROTECTALL(WARNING) will not at allow unauthorized access. This situation allows for a downgrade to a Category II.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including the value for the PROTECTALL Option. 

PROTECTALL is ACTIVATED and set to FAIL by issuing the command SETR PROTECTALL(FAIL).'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25377r514800_chk'
  tag severity: 'high'
  tag gid: 'V-223704'
  tag rid: 'SV-223704r604139_rule'
  tag stig_id: 'RACF-ES-000570'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25365r514801_fix'
  tag 'documentable'
  tag legacy: ['SV-107219', 'V-98115']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
