control 'SV-223919' do
  title 'IBM z/OS MCS consoles access authorization(s) for CONSOLE resource(s) must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS SYSCONS(*)

For each Console defined enter:
TSS WHOHAS SYSCONS(<console>)

If the ACID associated with each console has READ access to the corresponding resource defined in the SYSCONS resource class, this is not a finding.

If access authorization for SYSCONS resources restricts access to operations, the Master SCA, system programming personnel, or authorized personnel, this is not a finding.

If the console defined is not defined to the TSS SYSCONS resource class enter: 
TSS LIST (RDT) RESCLASS(SYSCONS)

If the SYSCONS resource class does not have the DEPROT attribute, this is a finding.

For each Console defined enter:
TSS WHOHAS(<CONSOLE>)

If the console defined is not defined to the TSS SYSCONS resource class enter: 
TSS LIST (RDT) RESCLASS(SYSCONS)

If the SYSCONS resource class does not have the DEPROT attribute, this is a finding.'
  desc 'fix', 'Ensure that all MCS consoles are defined to the SYSCONS resource class and READ access is limited to operators, and system programmers, or authorized personnel.

Review the MCS console resources defined to z/OS and the ACP and ensure they conform to those outlined below.

Each console defined in the CONSOLxx parmlib members is defined to TSS SYSCONS resource class and/or the SYSCONS resource class has the DEFPROT attribute.

Example:

TSS REPLACE(RDT) RESCLASS(SYSCONS) ATTR(DEFPROT)

The ACID associated with each console has access to the corresponding resource defined in the SYSCONS resource class.

Example:

TSS PERMIT(MMGMST) SYSCONS(MMGMST) ACCESS(READ)

Access authorization for SYSCONS resources restricts access to operations, the Master SCA, and system programming personnel.

TSS PERMIT(opersmpl) SYSCONS(MMGMST) ACCESS(READ)
TSS PERMIT(Master SCA) SYSCONS(MMGMST) ACCESS(READ)
TSS PERMIT(syspsmpl) SYSCONS(MMGMST) ACCESS(READ)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25592r811046_chk'
  tag severity: 'medium'
  tag gid: 'V-223919'
  tag rid: 'SV-223919r877760_rule'
  tag stig_id: 'TSS0-ES-000460'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25580r811047_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98545', 'SV-107649']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
