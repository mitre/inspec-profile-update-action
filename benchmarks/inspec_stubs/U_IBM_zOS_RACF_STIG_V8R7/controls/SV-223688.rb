control 'SV-223688' do
  title 'IBM RACF must limit access to System page data sets (i.e., PLPA, COMMON, and LOCALx) to system programmers.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Execute a dataset list of access for System page data sets (i.e., PLPA, COMMON, and LOCALx).

If ESM data set rules for system page data sets (PLPA, COMMON, and LOCAL) restrict access to only systems programming personnel, this is not a finding.

If ESM data set rules for system page data sets (PLPA, COMMON, and LOCAL) restrict auditors to READ only, this is not a finding.'
  desc 'fix', 'Configure the ESM data set rules for system page data sets (PLPA, COMMON, and LOCAL) to restrict access to only systems programming personnel.
Auditors may be allowed READ Access as approved by the ISSM.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25361r514752_chk'
  tag severity: 'medium'
  tag gid: 'V-223688'
  tag rid: 'SV-223688r604139_rule'
  tag stig_id: 'RACF-ES-000400'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25349r514753_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98081', 'SV-107185']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
