control 'SV-223444' do
  title 'IBM z/OS MCS consoles access authorization(s) for CONSOLE resource(s) must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Refer to the proper CONSOLxx member of SYS1.PARMLIB.

From a ACF Command screen enter:
ACF
SET RESOURCE(CON)
SET VERBOSE
LIST LIKE(-) 

NOTE: If CLASMAP defines CONSOLE as anything other than the default of TYPE(CON), replace CON below with the appropriate three letters.

If each console in the CONSOLxx member is defined to ACF2 with a corresponding resource rule for TYPE(CON), this is not a finding.

If each TYPE(CON) rule is defined with PREVENT access by default, this is not a finding.

If the logonid associated with each console has READ access to the corresponding resource defined in the CONSOLE resource class, this is not a finding.

If access authorization for CONSOLE resources restricts READ access to operations and system programming personnel, this is not a finding.'
  desc 'fix', "Configuration should ensure that all MCS consoles are defined to the CONSOLE resource class and READ access is limited to operators and system programmers.

Review the MCS console resources defined to z/OS and the ACP, and ensure they conform to those outlined below.

Each console defined in the CONSOLxx parmlib members is defined to ACF2 with a corresponding resource rule for TYPE(CON). 

Each TYPE(CON) rule is defined with PREVENT access by default.

The logonid associated with each console has READ access to the corresponding resource defined in the CONSOLE resource class.

Access authorization for CONSOLE resources restricts READ access to operations and system programming personnel.

Example:
$KEY(MZNC20) TYPE(CON) 
USERDATA(CONSOLE ID SECURITY) 
UID(sysprgmr) ALLOW
UID(oper) ALLOW
UID(MZNC20) ALLOW DATA(MZNC20 CONSOLE LOGONID ACCESS REQUIREMENTS) 
UID(*) PREVENT

SET R(CON)
COMPILE 'ACF2.MZN.CON(MZNC20)' STORE

F ACF2,REBUILD(CON)"
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25117r504464_chk'
  tag severity: 'medium'
  tag gid: 'V-223444'
  tag rid: 'SV-223444r533198_rule'
  tag stig_id: 'ACF2-ES-000230'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25105r504465_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-97585', 'SV-106689']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
