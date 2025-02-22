control 'SV-230209' do
  title 'The IBM RACF System REXX IRRPHREX security data set must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer to the zOS system REXXLIB concatenation found in SYS1. PARMLIB (AXR) for the data set that contains the REXX for Password exit named IRRPHREX and the defined AXRUSER.

If the following guidance is true, this is not a finding.

-RACF data set access authorizations restrict READ to AXRUSER, z/OS systems programming personnel, security personnel, and auditors.
-RACF data set access authorizations restrict UPDATE to security personnel using a documented change management procedure to provide a mechanism for access and revoking of access after use.
-All (i.e., failures and successes) data set access authorities (i.e., READ, UPDATE, and CONTROL) is logged.
-RACF data set access authorizations specify UACC(NONE) and NOWARNING.'
  desc 'fix', "Configure read access to be restricted to security administrators, systems programmers, and auditors.

Establish a procedure documented with the ISSM that defines a change management process to provide mechanism for granting Update access to security administrators on an exception basis. The process should contain procedures to revoke access when documented update is completed.

Configure all failures and successes data set access authorities for RACF data set that contains the Password exit to be logged.

Examples:
ad 'sys3.racf.rexxlib.**' uacc(none) owner(sys3) -
audit(all(read)) 
Permit 'sys3.racf.rexxlib.**' id(<syspsmpl> <secasmpl> <smplsmpl> AXRUSER) acc(r)
Permit 'sys3.racf.rexxlib.**' id(<secasmpl>) acc(u)"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-32541r767103_chk'
  tag severity: 'medium'
  tag gid: 'V-230209'
  tag rid: 'SV-230209r767105_rule'
  tag stig_id: 'RACF-ES-000365'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25345r767104_fix'
  tag 'documentable'
  tag legacy: ['SV-71007', 'V-56747']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
