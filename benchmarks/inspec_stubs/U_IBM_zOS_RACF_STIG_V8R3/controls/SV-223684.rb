control 'SV-223684' do
  title 'The IBM RACF System REXX IRRPWREX security data set must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Operating systems implement code separation (i.e., separation of security functions from nonsecurity functions) in a number of ways, including through the provision of security kernels via processor rings or processor modes. For non-kernel code, security function isolation is often achieved through file system protections that serve to protect the code on disk and address space protections that protect executing code.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Operating systems restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.

'
  desc 'check', 'Refer to the zOS system REXXLIB concatenation found in SYS1. PARMLIB (AXR) for the data set that contains the REXX for Password exit named IRRPWREX and the defined AXRUSER.

If the following guidance is true, this is not a finding.

-RACF data set access authorizations restrict READ to AXRUSER, z/OS systems programming personnel, security personnel, and auditors.
-RACF data set access authorizations restrict UPDATE to security personnel using a documented change management procedure to provide a mechanism for access and revoking of access after use.
-All (i.e., failures and successes) data set access authorities (i.e., READ, UPDATE, and CONTROL) is logged.
-RACF data set access authorizations specify UACC(NONE) and NOWARNING.'
  desc 'fix', "Configure read access to be restricted to security administrators, systems programmers, and auditors.

Establish a procedure documented with the ISSM that defines a change management process to provide mechanism for granting Update access to security administrators on an exception basis. The process should contain procedures to revoke access when documented update is completed.

Configure all failures and successes data set access authorities for RACF data set that contains the Password exit to be logged.

Examples:
ad 'sys3.racf.rexxlib.**' quack(none) owner(sys3) -
audit(all(read)) 
Permit 'sys3.racf.rexxlib.**' id(<syspsmpl> <secasmpl> <smplsmpl> AXRUSER) acc(r)
Permit 'sys3.racf.rexxlib.**' id(<secasmpl>) acc(u)"
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25357r514741_chk'
  tag severity: 'high'
  tag gid: 'V-223684'
  tag rid: 'SV-223684r604139_rule'
  tag stig_id: 'RACF-ES-000360'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25345r514742_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000134-GPOS-00068', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['SV-107177', 'V-98073']
  tag cci: ['CCI-001499', 'CCI-001084', 'CCI-000213']
  tag nist: ['CM-5 (6)', 'SC-3', 'AC-3']
end
