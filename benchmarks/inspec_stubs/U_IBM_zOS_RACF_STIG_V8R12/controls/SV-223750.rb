control 'SV-223750' do
  title 'IBM z/OS JESSPOOL resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
SETRopt list

If the JESSPOOL resource class is active, this is not a finding.'
  desc 'fix', 'Configure the JESSPOOL resource class to be active:

Use the RACF Command: SETROPTS CLASSACT(JESSPOOL).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25423r514938_chk'
  tag severity: 'medium'
  tag gid: 'V-223750'
  tag rid: 'SV-223750r604139_rule'
  tag stig_id: 'RACF-JS-000060'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25411r514939_fix'
  tag 'documentable'
  tag legacy: ['V-98207', 'SV-107311']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
