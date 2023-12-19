control 'SV-223683' do
  title 'IBM RACF access to SYS1.LINKLIB must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Execute a dataset list of access to SYS1.LINKLIB.

If the ESM data set rules for SYS1.LINKLIB allow inappropriate (e.g., global READ) access, this is a finding.

If data set rules for SYS1.LINKLIB do not restrict READ, UPDATE, and ALTER access to only systems programming personnel, this is a finding.

If data set rules for SYS1.LINKLIB do not restrict READ and UPDATE access to only domain level security administrators, this is a finding.

If data set rules for SYS1.LINKLIB do not restrict READ access to only system Level Started Tasks, authorized Data Center personnel, and auditors, this is a finding.

If data set rules for SYS1.LINKLIB do not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged, this is a finding.'
  desc 'fix', 'Configure the ESM rules for SYS1.LINKLIB to limit access to system programmers only and all update and allocate access is logged.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25356r514738_chk'
  tag severity: 'medium'
  tag gid: 'V-223683'
  tag rid: 'SV-223683r604139_rule'
  tag stig_id: 'RACF-ES-000350'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25344r514739_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125', 'SRG-OS-000362-GPOS-00149']
  tag 'documentable'
  tag legacy: ['V-98071', 'SV-107175']
  tag cci: ['CCI-000213', 'CCI-001499', 'CCI-001812', 'CCI-002235']
  tag nist: ['AC-3', 'CM-5 (6)', 'CM-11 (2)', 'AC-6 (10)']
end
