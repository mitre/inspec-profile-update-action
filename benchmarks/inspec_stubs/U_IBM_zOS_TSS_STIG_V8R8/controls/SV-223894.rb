control 'SV-223894' do
  title 'CA-TSS must limit Write or greater access to SYS1.SVCLIB to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Execute a data set list of access for SYS1.SVCLIB.

If all of the following are true, this is not a finding.

If any of the following are untrue, this is a finding.

ESM data set rules for SYS1.SVCLIB restrict WRITE or greater access to only z/OS systems programming personnel.
ESM data set rules for SYS1.SVCLIB specify that all (i.e., failures and successes) WRITE or greater access will be logged.'
  desc 'fix', 'Configure WRITE or greater access to SYS1.SVCLIB to be limited to system programmers only and all WRITE or greater access is logged and reviewed. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes for SYS1.SVCLIB. SYS1.SVCLIB contains SVCs and I/O appendages as such: they are very powerful and will be strictly controlled to avoid compromising system integrity.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25567r516081_chk'
  tag severity: 'high'
  tag gid: 'V-223894'
  tag rid: 'SV-223894r856065_rule'
  tag stig_id: 'TSS0-ES-000210'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25555r516082_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107599', 'V-98495']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
