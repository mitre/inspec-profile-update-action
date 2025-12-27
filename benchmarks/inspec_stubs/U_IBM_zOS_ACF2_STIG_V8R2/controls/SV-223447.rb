control 'SV-223447' do
  title 'CA-ACF2 must limit Write or greater access to SYS1.IMAGELIB to system programmers.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

'
  desc 'check', 'Execute a data set list of access for SYS1.IMAGELIB.

If the following guidance is true, this is not a finding.

 The ACP data set rules for SYS1.IMAGELIB allow inappropriate access.

 The ACP data set rules for SYS1.IMAGELIB do not restrict UPDATE and/or ALTER access to only systems programming personnel.

 The ACP data set rules for SYS1.IMAGELIB do not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.'
  desc 'fix', 'Configure UPDATE and/or ALLOCATE access to SYS1.IMAGELIB to be limited to system programmers only and all update and allocate access is logged.

Review access authorization to critical system files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required to protect SYS1.IMAGELIB.

SYS1.IMAGELIB is automatically APF-authorized. This data set contains modules, images, tables, and character sets which are essential to system print services.'
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25120r504473_chk'
  tag severity: 'high'
  tag gid: 'V-223447'
  tag rid: 'SV-223447r533198_rule'
  tag stig_id: 'ACF2-ES-000260'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25108r504474_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-97591', 'SV-106695']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
