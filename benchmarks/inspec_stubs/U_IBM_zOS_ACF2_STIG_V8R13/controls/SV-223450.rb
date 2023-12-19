control 'SV-223450' do
  title 'CA-ACF2 must limit Write or greater access to all LPA libraries to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'From any ISPF input line, enter TSO ISRDDN LPA. 

If all of the following are untrue, this is not a finding.

If any of the following is true, this is a finding.

The ACP data set rules for LPA libraries do not restrict WRITE and/or ALLOCATE access to only z/OS systems programming personnel.

The ACP data set rules for LPA libraries do not specify that all (i.e., failures and successes) WRITE and/or ALLOCATE access will be logged.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to protect LPA Libraries.

Configure the update and allocate access to all LPA libraries to be limited to system programmers only and all update and allocate access is logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25123r918592_chk'
  tag severity: 'high'
  tag gid: 'V-223450'
  tag rid: 'SV-223450r918593_rule'
  tag stig_id: 'ACF2-ES-000290'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25111r504483_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-106701', 'V-97597']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
