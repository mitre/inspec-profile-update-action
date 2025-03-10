control 'SV-223905' do
  title 'CA-TSS allocate access to system user catalogs must be limited to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'From the ISPF Command Shell enter:
LISTCat USERCATALOG ALL NOPREFIX

Review the ESM data set rules for each usercatalog defined.

If the data set rules for User Catalogs do not restrict ALTER access to only z/OS systems programming personnel, this is a finding.


If Products or procedures requiring system programmer access for system-level maintenance meet the following specific case, this is not a finding:
- The batch job or procedure must be documented in the SITE Security Plan. 
- Reside in a data set that is restricted to systems programmers’ access only.

If the data set rules for User Catalogs do not specify that all (i.e., failures and successes) ALTER access will be logged, this a finding.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required to protect USER CATALOGS.

Configure ESM rules for allocate access to USER CATALOGS, limited to system programmers only, and all allocate access is logged.

Configure ESM rules for the USER CATALOGS to allow any Products or procedures system programmer access for system-level maintenance that meet the following specific case:
- The batch job or procedure must be documented in the SITE Security Plan. 
- Reside in a data set that is restricted to systems programmers’ access only.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25578r695471_chk'
  tag severity: 'medium'
  tag gid: 'V-223905'
  tag rid: 'SV-223905r695473_rule'
  tag stig_id: 'TSS0-ES-000320'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25566r695472_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98517', 'SV-107621']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
