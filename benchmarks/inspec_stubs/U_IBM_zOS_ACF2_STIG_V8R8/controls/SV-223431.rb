control 'SV-223431' do
  title 'CA-ACF2 must properly define users that have access to the CONSOLE resource in the TSOAUTH resource class.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'NOTE: If CLASMAP defines TSOAUTH or OPERCMDS as anything other than the default of TYPE(TSO) or TYPE(OPR), replace TSO or OPR below with the appropriate three letters.

If the CONSOLE resource is not defined to the TSOAUTH resource class, this is not a finding.

At the discretion of the ISSO, users may be allowed to issue z/OS system commands from a TSO session. With this in mind, configure the following for users granted the CONSOLE resource in the TSOAUTH resource class or users assigned the CONSOLE attribute:

 Logonids are restricted to the INFO level on the AUTH field specified in the OPERPARM segment of the user profile record.
 Logonids are restricted to READ access to the MVS.MCSOPER.userid resource defined in the OPERCMDS resource class (i.e., resource rules for TYPE(OPR)).

If all of the above are true, this is not a finding.

If any of the above are untrue, this is a finding.'
  desc 'fix', "Configuration should ensure that all users that have access to the CONSOLE resource in the TSOAUTH resource class are properly defined. 

Ensure the CONSOLE resource is not defined to the TSOAUTH resource class.

Example:
$KEY(CONSOLE) TYPE(TSO)
- UID(*) PREVENT

At the discretion of the ISSO, users may be allowed to issue z/OS system commands from a TSO session. With this in mind, ensure the following items are in effect for users granted the CONSOLE resource in the TSOAUTH resource class or users assigned the CONSOLE attribute:

Logonids are restricted to the INFO level on the AUTH field specified in the OPERPARM segment of the user profile record.

Logonids are restricted to READ access to the MVS.MCSOPER.userid resource defined in the OPERCMDS resource class (i.e., resource rules for TYPE(OPR)).

Example:
$KEY(MVS) TYPE(OPR)
MCSOPER.logonid UID(sysprgmr) SERVICE(READ) ALLOW

COMPILE ' ACF2.MVA.OPR(MVS)' STORE

F ACF2,REBUILD(OPR)"
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25104r504431_chk'
  tag severity: 'medium'
  tag gid: 'V-223431'
  tag rid: 'SV-223431r533198_rule'
  tag stig_id: 'ACF2-ES-000100'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25092r504432_fix'
  tag 'documentable'
  tag legacy: ['SV-106663', 'V-97559']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
