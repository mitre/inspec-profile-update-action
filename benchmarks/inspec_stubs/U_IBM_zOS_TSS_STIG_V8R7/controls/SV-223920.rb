control 'SV-223920' do
  title 'CA-TSS must properly define users that have access to the CONSOLE resource in the TSOAUTH resource class.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'TSS WHOOWNS TSOAUTH(*)
If the Console is not defined to TSOAuth RESOURCE CLASS this is Not Applicable.

Refer to the CONSOLxx member of SYS1.PARMLIB. 

For each Console defined if the following is true, this is not a finding.

-User ACIDs are restricted to the INFO level in the MCSAUTH attribute.
-User ACIDs are restricted to READ access to the MVS.MCSOPER.acid resource defined in the OPERCMDS resource class.
-User ACIDs and/or profile ACIDs are restricted to the CONSOLE resource defined in the TSOAUTH resource class.

If any of the above are untrue, this is a finding.'
  desc 'fix', 'Evaluate the impact of correcting any deficiencies. Develop a plan of action and implement the required changes.

At the discretion of the ISSO, users may be allowed to issue z/OS system commands from a TSO session. With this in mind, ensure the following items are in effect for users granted the TSO CONSOLE privilege: 
-User ACIDs are restricted to the INFO level in the MCSAUTH attribute. 
-User ACIDs are restricted to READ access to the MVS.MCSOPER.acid resource defined in the OPERCMDS resource class. 
-User ACIDs and/or profile ACIDs are restricted to the CONSOLE resource defined in the TSOAUTH resource class. 

For Example:
TSS ADDTO (userid) MCSAUTH(INFO)
TSS PERMIT(userid) OPERCMDS(MVS.MCSOPER.userid) 
ACCESS(READ) ACTION(AUDIT)
TSS PERMIT(oprprofileacid) TSOAUTH(CONSOLE) 
ACCESS(READ) ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25593r516159_chk'
  tag severity: 'medium'
  tag gid: 'V-223920'
  tag rid: 'SV-223920r561402_rule'
  tag stig_id: 'TSS0-ES-000470'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25581r516160_fix'
  tag 'documentable'
  tag legacy: ['V-98547', 'SV-107651']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
