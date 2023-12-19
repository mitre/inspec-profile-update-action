control 'SV-223853' do
  title 'IBM z/OS default profiles must be defined in the corresponding FACILITY Class Profile for classified systems.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'If the system is not classified, this is Not Applicable.

From a command input screen enter:

RLIST FACILITY (BPX.UNIQUE.USER) ALL
Examine APPLICATION DATA for userid

If system is classified and a userid is are not defined in the Application Data field in the BPX.UNIQUE.USER resource in the FACILITY report, this is not a finding.'
  desc 'fix', "If system is classified a userid should not be defined in the application data field of the FACILITY report.

The sample commands below show the required security parameters required for the default user:

AU OEDFLTU DFLTGRP(OEDFLTG) NAME('OE DEFAULT USER') NOPASS -
OMVS(UID(99999) HOME('/u/oeflt') PROGRAM('/bin/echo')) - 
DATA('DEFAULT OMVSUSERID ADDED WITH SOER5') 

RDEF FACILITY BPX. UNIQUE.USER APPLDATA() - 
DATA('ADDED TO SUPPORT THE DEFAULT USER') UACC(NONE) OWNER(ADMIN) 

SETR RACLIST(FACILITY) REFRESH"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25526r515247_chk'
  tag severity: 'medium'
  tag gid: 'V-223853'
  tag rid: 'SV-223853r604139_rule'
  tag stig_id: 'RACF-US-000160'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25514r515248_fix'
  tag 'documentable'
  tag legacy: ['V-98413', 'SV-107517']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
