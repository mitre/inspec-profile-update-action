control 'SV-223441' do
  title 'CA-ACF2 must limit Write or greater access to SYS1.UADS To system programmers only and read and update access must be limited to system programmer personnel and/or security personnel.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'The ACF2 data set rules for SYS1.UADS restrict ALLOCATE access to only z/OS systems programming personnel.

The ACF2 data set rules for SYS1.UADS restrict READ and/or WRITE access to z/OS systems programming personnel and/or security personnel.

The ACF2 data set rules for SYS1.UADS restrict READ access to auditors as documented in the Security Plan.

The ACF2 data set rules for SYS1.UADS specify that all (i.e., failures and successes) data set access authorities (i.e., READ, WRITE, ALLOCATE, and CONTROL) will be logged.

If all of the above are untrue, this is not a finding.

If any of the above is true, this is a finding.'
  desc 'fix', 'Evaluate the impact of correcting any deficiency. Develop a plan of action and implement the changes as required to protect SYS1.UADS.

SYS1.UADS WRITE or Greater authority is limited to the systems programming staff. 

READ and/or WRITE access should be limited to the security staff.

READ access is limited to Auditors when included in the site security plan

Configure allocate access to SYS1.UADS to be limited to system programmers only; Read and Update access to SYS1.UADS to be limited to system programmer personnel and/or security personnel and all dataset access is logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25114r918580_chk'
  tag severity: 'high'
  tag gid: 'V-223441'
  tag rid: 'SV-223441r918582_rule'
  tag stig_id: 'ACF2-ES-000200'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25102r918581_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-106683', 'V-97579']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
