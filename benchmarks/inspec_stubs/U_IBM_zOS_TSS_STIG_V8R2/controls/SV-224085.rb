control 'SV-224085' do
  title 'The CA-TSS HFSSEC resource class must be defined with DEFPROT.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS
If the Control Option is HFSSEC(OFF), this is Not Applicable.

Enter:
TSS LIST RDT
If the DEFPROT attribute is specified for the HFSSEC resource class in the RDT, this is not a finding.'
  desc 'fix', 'Ensure that the HFSSEC resource class has the attribute DEFPROT.

For Example:

TSS REPLACE(RDT) RESCLASS(HFSSEC) ATTR(DEFPROT)'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25758r516654_chk'
  tag severity: 'high'
  tag gid: 'V-224085'
  tag rid: 'SV-224085r561402_rule'
  tag stig_id: 'TSS0-US-000120'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25746r516655_fix'
  tag 'documentable'
  tag legacy: ['V-98877', 'SV-107981']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
