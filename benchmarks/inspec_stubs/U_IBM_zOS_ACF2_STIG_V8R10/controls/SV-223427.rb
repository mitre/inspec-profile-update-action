control 'SV-223427' do
  title 'IBM z/OS system commands must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From a Command input line enter:
SET RESOURCE(OPR)
SET VERBOSE
LIST LIKE(MVS-)

NOTE: If CLASMAP defines OPERCMDS as anything other than the default of TYPE(OPR), replace OPR with the appropriate three letters.

If the MVS resource is defined to the OPERCMDS class with a default access of PREVENT, and all access logged, i.e., MVS.** is defined with access of PREVENT, this is not finding.

If Access to z/OS system commands defined in the table entitled MVS commands, RACF access authorities, and resource names, in the IBM z/OS MVS System Commands manual, is restricted to the appropriate personnel (e.g., operations staff, systems programming personnel, general users) as determined in the Documented site Security Plan, this is not a finding.

Note: Display commands and others as deemed by the site IAW site security plan may be allowed for all users with no logging. The (MVS.SEND) Command will not be a finding if used by all.'
  desc 'fix', "Configure z/OS Sensitive System Commands to be defined to the OPERCMDS resource class. Only limited number of authorized people are able to issue these commands. All access is logged.

Configure the MVS resource to be defined to the OPERCMDS class with a default access of PREVENT, all access is logged, and access is restricted to the appropriate personnel (e.g., operations staff, systems programming personnel, general users).

Note: Ensure access to z/OS system commands defined in the MVS commands, RACF access authorities, and resource names, in the IBM z/OS MVS System Commands, is restricted to the appropriate personnel (e.g., operations staff, systems programming personnel, general users).

Example for ACF2:
$KEY(MVS) TYPE(OPR) 
ACTIVATE.- UID(sysprgmr) LOG 
ACTIVATE.- UID(*) PREVENT 

SET R(OPR)
COMPILE 'ACF2.MVA.OPR(MVS)' STORE

F ACF2,REBUILD(OPR)"
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25100r504419_chk'
  tag severity: 'medium'
  tag gid: 'V-223427'
  tag rid: 'SV-223427r533198_rule'
  tag stig_id: 'ACF2-ES-000060'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25088r504420_fix'
  tag 'documentable'
  tag legacy: ['V-97551', 'SV-106655']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
