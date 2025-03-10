control 'SV-223869' do
  title 'IBM z/OS System datasets used to support the VTAM network must be properly secured.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Determine data set names containing all VTAM start options, configuration lists, network resource definitions, commands, procedures, exit routines, all SMP/E TLIBs, and all SMP/E DLIBs used for installation and in development/production VTAM environments.

If RACF data set rules for all VTAM system data sets restrict access to only network systems programming staff, this is not a finding.

If RACF data set rules for all VTAM system data sets all READ access to auditors only, this is not a finding.'
  desc 'fix', "Configure RACF data set rules for all VTAM system data sets restrict access to only network systems programming staff. These data sets include libraries containing VTAM load modules and exit routines, and VTAM start options and definition statements.

Auditors may have READ access as documented by and approved by the ISSM.

The following sample RACF commands show proper definitions/permissions for VTAM datasets:

AD 'SYS1.VTAM*.**' UACC(NONE) OWNER(SYS1) - 
AUDIT(SUCCESS(UPDATE) FAILURES(READ)) - 
DATA('IBM VTAM DS PROFILE: REF SRR PDI ZVTM0018') 
PE 'SYS1.VTAM.**' ID(<syspsmpl>) ACC(A) 

AD 'SYS1.VTAMLIB.**' UACC(NONE) OWNER(SYS1) - 
AUDIT(SUCCESS(UPDATE) FAILURES(READ)) - 
DATA('IBM VTAM APF DS PROFILE: REF SRR PDI ZVTM0018') 
PE 'SYS1.VTAMLIB.**' ID(<syspsmpl>) ACC(A) 

AD 'SYS1.VTAM.SISTCLIB.**' UACC(NONE) OWNER(SYS1) -
AUDIT(SUCCESS(UPDATE) FAILURES(READ)) - 
DATA('IBM VTAM APF DS PROFILE: REF SRR PDI ZVTM0018') 
PE 'SYS1.VTAM.SISTCLIB.**' ID(<syspsmpl>) ACC(A) 

AD 'SYS3.VTAM.**' UACC(NONE) OWNER(SYS3) - 
AUDIT(SUCCESS(UPDATE) FAILURES(READ)) - 
DATA('VTAM CUSTOMIZED DS: REF SRR PDI ZVTM0018') 
PE 'SYS3.VTAM.**' ID(<syspsmpl>) ACC(A) 

AD 'SYS3.VTAMLIB.**' UACC(NONE) OWNER(SYS3) - 
AUDIT(SUCCESS(UPDATE) FAILURES(READ)) - 
DATA('IBM VTAM APF DS PROFILE: REF SRR PDI ZVTM0018')
PE 'SYS3.VTAMLIB.**' ID(<syspsmpl>) ACC(A) 

SETR GENERIC(DATASET) REFRESH"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25542r515295_chk'
  tag severity: 'medium'
  tag gid: 'V-223869'
  tag rid: 'SV-223869r604139_rule'
  tag stig_id: 'RACF-VT-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25530r515296_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['V-98445', 'SV-107549']
  tag cci: ['CCI-001499', 'CCI-000213']
  tag nist: ['CM-5 (6)', 'AC-3']
end
