control 'SV-223991' do
  title 'IBM z/OS JESSPOOL resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer the JES2PARM member of SYS1.PARMLIB. Review the JESSPOOL resource in the JESINPUT resource class:

NOTE: If the JESSPOOL resource is not defined within the JES2 parameters, the resource in the JESINPUT resource class does not have to be owned.

From the ISPF Command Shell enter:

TSS WHOOWNS JESINPUT(JESSPOOL)

If the JESSPOOL resource is owned by generic and/or fully qualified entries in the JESINPUT resource class, this is not a finding.'
  desc 'fix', 'Review the JES2 parameters to determine the localnodeid by searching for OWNNODE in the NJEDEF statement, and then searching for NODE(nnnn) (where nnnn is the value specified by OWNNODE). The NAME parameter value specified on this NODE statement is the localnodeid.

The following command may be used to establish default protection for resources defined to the JESSPOOL resource class:

TSS ADDTO(deptacid) JESSPOOL(localnodeid.)

Due to the protection established with the previous command, the following command should be issued to ensure users are able to access their own spool data:

TSS PERMIT(ALL) JESSPOOL(localnodeid.%) ACCESS(ALL)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25664r516372_chk'
  tag severity: 'medium'
  tag gid: 'V-223991'
  tag rid: 'SV-223991r561402_rule'
  tag stig_id: 'TSS0-JS-000070'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25652r516373_fix'
  tag 'documentable'
  tag legacy: ['V-98689', 'SV-107793']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
