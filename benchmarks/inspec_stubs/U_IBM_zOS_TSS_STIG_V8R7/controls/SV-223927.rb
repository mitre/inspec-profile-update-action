control 'SV-223927' do
  title 'The CA-TSS ALL record must have appropriate access to Facility Matrix Tables.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Review the ALL record for the assignment of FACILITY.

If CA-Top Secret facilities are granted via the ALL record, with the exception of DFHSM/HSM, this is a finding. 

The DFHSM/HSM FACILITY can be determined by reviewing FACLIST for the FACILITY that contains INITPGM=ARC.'
  desc 'fix', 'Review ALL record for FACILITY access. Evaluate the impact of correcting the deficiency. Develop a plan of action and remove access.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25600r516180_chk'
  tag severity: 'medium'
  tag gid: 'V-223927'
  tag rid: 'SV-223927r561402_rule'
  tag stig_id: 'TSS0-ES-000530'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25588r516181_fix'
  tag 'documentable'
  tag legacy: ['SV-107665', 'V-98561']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
