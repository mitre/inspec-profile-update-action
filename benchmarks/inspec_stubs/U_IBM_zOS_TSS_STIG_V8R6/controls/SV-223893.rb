control 'SV-223893' do
  title 'CA-TSS access to SYS1.LINKLIB must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Execute a data set list of access to SYS1.LINKLIB.

If the ESM data set rules for SYS1.LINKLIB allow inappropriate (e.g., global READ) access, this is a finding.

If data set rules for SYS1.LINKLIB do not restrict READ, WRITE or greater access to only systems programming personnel, this is a finding.

If data set rules for SYS1.LINKLIB do not restrict READ and UPDATE access to only domain level security administrators, this is a finding.

If data set rules for SYS1.LINKLIB do not restrict READ access to only system Level Started Tasks, authorized Data Center personnel, and auditors, this is a finding.

If data set rules for SYS1.LINKLIB do not specify that all (i.e., failures and successes) WRITE or greater access will be logged, this is a finding.'
  desc 'fix', 'Configure the ESM rules for SYS1.LINKLIB limit access to system programmers only and all WRITE or greater access is logged.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25566r516078_chk'
  tag severity: 'medium'
  tag gid: 'V-223893'
  tag rid: 'SV-223893r561402_rule'
  tag stig_id: 'TSS0-ES-000200'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25554r516079_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000362-GPOS-00149', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107597', 'V-98493']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-001812']
  tag nist: ['AC-3', 'CM-5 (6)', 'CM-11 (2)']
end
