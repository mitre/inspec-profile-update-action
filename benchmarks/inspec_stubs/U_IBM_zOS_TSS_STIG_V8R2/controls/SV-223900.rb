control 'SV-223900' do
  title 'CA-TSS must limit Write or greater access to SYS1.NUCLEUS to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Execute a dataset list of access for SYS1.NUCLEUS.

If all of the following are untrue, there is not a finding.

If any of the following is true, this is a finding.

The ACP data set rules for SYS1.NUCLEUS do not restrict WRITE or greater access to only z/OS systems programming personnel.
The ACP data set rules for SYS1.NUCLEUS do not specify that all (i.e., failures and successes) WRITE or greater access will be logged.'
  desc 'fix', 'Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to protect SYS1.NUCLEUS.

Configure the WRITE or greater access to SYS1.NUCLEUS to be limited to system programmers only and all WRITE or greater access is logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25573r516099_chk'
  tag severity: 'high'
  tag gid: 'V-223900'
  tag rid: 'SV-223900r561402_rule'
  tag stig_id: 'TSS0-ES-000270'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25561r516100_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98507', 'SV-107611']
  tag cci: ['CCI-001499', 'CCI-000213', 'CCI-002235']
  tag nist: ['CM-5 (6)', 'AC-3', 'AC-6 (10)']
end
