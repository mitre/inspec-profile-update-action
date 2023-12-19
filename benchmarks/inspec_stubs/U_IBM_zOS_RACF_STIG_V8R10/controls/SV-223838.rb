control 'SV-223838' do
  title 'The IBM z/OS UNIX SUPERUSER resources must be protected in accordance with guidelines.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
RL UNIXPRIV * AUTHUSER

If the RACF rules for the SUPERUSER resource specify a default access of NONE, this is not a finding.

If there are no RACF rules that allow access to the SUPERUSER resource, this is not a finding.

If there is no RACF rule for CHOWN.UNRESTRICTED defined, this is not a finding.

If the RACF rules for each of the SUPERUSER resources listed in the z/OS UNIX System Services Planning, Establishing UNIX security, specify a default access of NONE, this is not a finding.

If the RACF rules for each of the SUPERUSER resources listed in the z/OS UNIX System Services Planning, Establishing UNIX security, restrict access to appropriate system tasks or systems programming personnel, this is not a finding.'
  desc 'fix', "Configure all SUPERUSER resources for the UNIXPRIV resource class to be restricted to appropriate system tasks and/or system programming personnel.

-The RACF rules for the SUPERUSER resource specify a default access of NONE.
-There are no RACF rules that allow access to the SUPERUSER resource.
-There is no RACF rule for CHOWN.UNRESTRICTED defined.
-The RACF rules for each of the SUPERUSER resources listed in the z/OS UNIX System Services Planning, Establishing UNIX security, specify a default access of NONE.
-The RACF rules for each of the SUPERUSER resources listed in the z/OS UNIX System Services Planning, Establishing UNIX security, restrict access to appropriate system tasks or systems programming personnel.

Sample Commands:
RDEF UNIXPRIV SUPERUSER.** UACC(NONE) OWNER(ADMIN) DATA('REFERENCE ZUSS0023') AUDIT(ALL(READ))
/* do not permit any users/groups to this resource */

SR CLASS(UNIXPRIV) MASK(CHOWN.UNRESTRICTED)
/* delete if found */

PE SUPERUSER.FILESYS.** CL(UNIXPRIV) ID(<SYSPsmpl>)"
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25511r515202_chk'
  tag severity: 'high'
  tag gid: 'V-223838'
  tag rid: 'SV-223838r604139_rule'
  tag stig_id: 'RACF-US-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25499r515203_fix'
  tag 'documentable'
  tag legacy: ['V-98383', 'SV-107487']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
