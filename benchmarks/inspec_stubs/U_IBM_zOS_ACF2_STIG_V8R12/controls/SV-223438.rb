control 'SV-223438' do
  title 'CA-ACF2 must limit access to System page data sets (i.e., PLPA, COMMON, and LOCALx) to system programmers.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Execute a data set list of access for System page data sets (i.e., PLPA, COMMON, and LOCALx).

If the ESM data set rules for System page data sets (i.e., PLPA, COMMON, and LOCALx) do not restrict access to only systems programming personnel, this is a finding.

If ESM data set rules for system page data sets (PLPA, COMMON, and LOCAL) restrict auditors to READ only, this is not a finding.'
  desc 'fix', 'Configure the ESM data set rules for system page data sets (PLPA, COMMON, and LOCAL) to restrict access to only systems programming personnel.
Auditors may be allowed READ Access as approved by the ISSM.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25111r500445_chk'
  tag severity: 'medium'
  tag gid: 'V-223438'
  tag rid: 'SV-223438r533198_rule'
  tag stig_id: 'ACF2-ES-000170'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25099r500446_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-106677', 'V-97573']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
