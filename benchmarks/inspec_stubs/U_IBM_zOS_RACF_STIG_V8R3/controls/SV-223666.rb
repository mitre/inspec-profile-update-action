control 'SV-223666' do
  title 'IBM RACF access to the System Master Catalog must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Refer to SYSCATxx member of SYS1.NUCLEUS.

Multiple SYSCATxx members may be defined. If so, refer to Master Catalog message for IPL.

If the member is not found, refer to the appropriate LOADxx member of SYS1.PARMLIB.

If data set rules for the Master Catalog do not restrict greater than “READ” access to only z/OS systems programming personnel, this is a finding.

If Products or procedures requiring system programmer access for system-level maintenance meet the following specific case, this is not a finding:
- The batch job or procedure must be documented in the SITE Security Plan. 
- Reside in a data set that is restricted to systems programmers’ access only. 

If dataset rules for the Master Catalog do not specify that all (i.e., failures and successes) greater than “READ” access will be logged, this is a finding.'
  desc 'fix', 'Review access authorization to critical system files.

Evaluate the impact of correcting the deficiency.

Develop a plan of action and implement the changes as required to protect the MASTER CATALOG.

Configure the ESM rules for system catalog to only allow access above “READ” to systems programmers and those authorized by the ISSM/ISSO.

Configure ESM rules for the master catalog to allow access above “READ” to systems programmers ONLY.

Configure ESM rules for the master catalog to allow any products or procedures system programmer access for system-level maintenance that meets the following specific case:
- The batch job or procedure must be documented in the SITE Security Plan. 
- Reside in a data set that is restricted to systems programmers’ access only.
All greater than read access must be logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25339r572051_chk'
  tag severity: 'high'
  tag gid: 'V-223666'
  tag rid: 'SV-223666r604139_rule'
  tag stig_id: 'RACF-ES-000180'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25327r572052_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107141', 'V-98037']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
