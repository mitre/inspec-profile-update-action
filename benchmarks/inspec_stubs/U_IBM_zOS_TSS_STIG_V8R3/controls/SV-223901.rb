control 'SV-223901' do
  title 'CA-TSS must limit Write or greater access to libraries that contain PPT modules to system programmers only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Review program entries in the IBM Program Properties Table (PPT). You may use a third-party product to examine these entries however, to determine program entries issue the following command from an ISPF command line:
TSO ISRDDN LOAD IEFSDPPT
Press Enter.

For each module identified in the "eyecatcher" if all of the following are untrue, this is not a finding.

If any of the following is true, this is a finding.

The ACP data set rules for libraries that contain PPT modules do not restrict WRITE or greater access to only z/OS systems programming personnel.
The ACP data set rules for libraries that contain PPT modules do not specify that all WRITE or greater access will be logged.'
  desc 'fix', 'Configure the WRITE or greater access to libraries containing PPT modules to be limited to system programmers only and all WRITE or greater access is logged.'
  impact 0.3
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25574r516102_chk'
  tag severity: 'low'
  tag gid: 'V-223901'
  tag rid: 'SV-223901r561402_rule'
  tag stig_id: 'TSS0-ES-000280'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25562r516103_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98509', 'SV-107613']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'AC-6 (10)']
end
