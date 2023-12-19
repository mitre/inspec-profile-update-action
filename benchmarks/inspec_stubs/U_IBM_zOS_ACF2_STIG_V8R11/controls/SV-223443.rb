control 'SV-223443' do
  title 'CA-ACF2 access to the System Master Catalog must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', %q(Refer to SYSCATxx member of SYS1.NUCLEUS.
Multiple SYSCATxx members may be defined if so refer to Master Catalog message for IPL.
If the member is not found, refer to the appropriate LOADxx member of SYS1.PARMLIB.

If data set rules for the Master Catalog do not restrict greater than "READ" access to only z/OS systems programming personnel, this is a finding.

If Products or procedures requiring system programmer access for system level maintenance meet the following specific case:
- The batch job or procedure must be documented in the SITE Security Plan. 
- Reside in a data set that is restricted to systems programmers' access only. 
If the above is true, this is not a finding.

If data set rules for the Master Catalog do not specify that all (i.e., failures and successes) greater than "READ" access will be logged, this is a finding.)
  desc 'fix', %q(Review access authorization to critical system files.

Evaluate the impact of correcting the deficiency.

Develop a plan of action and implement the changes as required to protect the MASTER CATALOG.

Configure the ESM rules for system master catalog to only allow access above "READ" to systems programmers and those authorized by the Site Security Plan.

Configure ESM rules for the system master catalog to allow access above "READ" to systems programmers ONLY.

Configure ESM rules for the system master catalog to allow any Products or procedures system programmer access for system level maintenance that meet the following specific case:
- The batch job or procedure must be documented in the SITE Security Plan. 
- Reside in a data set that is restricted to systems programmers' access only. 
All greater than read access must be logged.)
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25116r836646_chk'
  tag severity: 'high'
  tag gid: 'V-223443'
  tag rid: 'SV-223443r836648_rule'
  tag stig_id: 'ACF2-ES-000220'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25104r836647_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-97583', 'SV-106687']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
