control 'SV-223435' do
  title 'CA-ACF2 allocate access to system user catalogs must be properly protected.'
  desc 'Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
LISTCat USERCATALOG ALL NOPREFIX

Review the ESM data set rules for each usercatalog defined.

If the data set rules for User Catalogs do not restrict ALTER access to only z/OS systems programming personnel, this is a finding.

If Products or procedures requiring system programmer access for system level maintenance meet the following specific case:
- The batch job or procedure must be documented in the SITE Security Plan.
- Reside in a data set that is restricted to systems programmers’ access only. 
If the above is true, this is not a finding.

If the data set rules for User Catalogs do not specify that all (i.e., failures and successes) ALTER access will be logged, this is a finding.

Note: If the USER CATALOGS contain SMS managed data sets READ access is sufficient to allow user operations. If the USER CATALOGS do not contain SMS managed dataseets UPDATE access is required for user operation.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required to protect USER CATALOGS.

Configure ESM rules for allocate access to USER CATALOGS, limited to system programmers only, and all allocate access is logged.

Configure ESM rules for the USER CATALOGS to allow any Products or procedures system programmer access for system-level maintenance that meets the following specific case:
- The batch job or procedure must be documented in the SITE Security Plan.
- Reside in a data set that is restricted to systems programmers’ access only.   

Note: If the USER CATALOGS contain SMS managed data sets READ access is sufficient to allow user operations. If the USER CATALOGS do not contain SMS managed dataseets UPDATE access is required for user operation.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25108r810989_chk'
  tag severity: 'medium'
  tag gid: 'V-223435'
  tag rid: 'SV-223435r811026_rule'
  tag stig_id: 'ACF2-ES-000140'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25096r811025_fix'
  tag 'documentable'
  tag legacy: ['V-97567', 'SV-106671']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
