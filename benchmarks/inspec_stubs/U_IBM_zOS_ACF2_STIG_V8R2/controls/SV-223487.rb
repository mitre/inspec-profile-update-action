control 'SV-223487' do
  title 'ACF2 BACKUP GSO record must be defined with a TIME value specifies greater than 00 unless the database is shared and backed up on another system.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ACF command screen enter:
SET CONTROL(GSO)
LIST LIKE(BACKUP-)

If the GSO BACKUP record values conform to the following requirements, this is not a finding.

Example: 
CPUID() PRISPACE(5) SECSPACE(5) STRING(S ACFBKUP) TIME(00:01) WORKUNIT(VIO)

If there is any deviation from the above requirements in the GSO BACKUP record values, this is a finding.'
  desc 'fix', 'Configure the BACKUP GSO value to specify a time field and Time(00:00 ) is not specified unless the database is shared and backed up on another system.

CPUID() PRISPACE(5) SECSPACE(5) STRING(S ACFBKUP) TIME(00:01) WORKUNIT(VIO)

Example: 
SET C(GSO)
INSERT BACKUP CPUID() PRISPACE(5) SECSPACE(5) STRING(S ACFBKUP) TIME(00:01) WORKUNIT(VIO) 

F ACF2,REFRESH(BACKUP)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25160r504567_chk'
  tag severity: 'medium'
  tag gid: 'V-223487'
  tag rid: 'SV-223487r533198_rule'
  tag stig_id: 'ACF2-ES-000690'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25148r504568_fix'
  tag 'documentable'
  tag legacy: ['V-97673', 'SV-106777']
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
