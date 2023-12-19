control 'SV-223929' do
  title 'IBM z/OS DASD Volume access greater than CREATE found in the CA-TSS database must be limited to authorized information technology personnel requiring access to perform their job duties.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS VOLUME(*) 

For each volume identified issue WHOHAS (<volume id>)

If access authorizations greater than CREATE (e.g., CONTROL or ALL) granted for DASD volumes are within the requirements in the site security plan, this is not a finding.

If access authorization for volumes exceeds the requirements without justification, this is a finding.

NOTE: Domain-level DASD Administrators who are responsible for the Domain level DASD/storage administration. Volume level access to those team members who are directly responsible and perform Domain level DASD/Storage administration may be granted access to all volumes via PRIVPGM controls.'
  desc 'fix', 'Ensure that DASD VOLUME access authorization greater than CREATE is not permitted unless authorized by the ISSO.

Review all access to DASD VOLUMEs. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the required changes.

*Noted Exception: Domain level DASD Administrators who are responsible for the Domain level DASD/storage administration. Volume level access to those team members who are directly responsible and perform Domain level DASD/Storage administration may be granted access to all volumes via PRIVPGM controls.

Domain Level DASD/Storage administrators access should be granted VOL(*ALL*)ACC(ALL)ACTION(AUDIT)PRIVPGM(list of privileged programs)'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25602r516186_chk'
  tag severity: 'high'
  tag gid: 'V-223929'
  tag rid: 'SV-223929r877770_rule'
  tag stig_id: 'TSS0-ES-000560'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25590r516187_fix'
  tag 'documentable'
  tag legacy: ['V-98565', 'SV-107669']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
