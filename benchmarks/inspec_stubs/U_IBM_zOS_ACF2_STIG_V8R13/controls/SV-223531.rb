control 'SV-223531' do
  title 'IBM z/OS JES2 system commands must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'NOTE: If CLASMAP defines OPERCMDS as anything other than TYPE(OPR), replace OPR below with the appropriate three letters.

From the ACF command screen enter:
SET RESOURCE(OPR)
LIST LIKE(JES-)

If the JES2.- resource is defined to the OPERCMDS class with a default access of PREVENT and all access is logged, this is not a finding.

If access to JES2 system commands defined in the table in the IBM JES2 Initialization and Tuning Guide titled "JES2 commands with profile names and minimum required authority" is restricted to the appropriate personnel (e.g., operations staff, systems programming personnel, general users), this is not a finding.

If all elevated access to JES2 system commands is logged, this is not a finding.'
  desc 'fix', %q(Review the GSO definitions. If CLASMAP defines OPERCMDS as anything other than TYPE(OPR), replace OPR below with the appropriate three letters.

Review resource rules for TYPE(OPR).

Define the JES2.- resource is defined to the OPERCMDS class with a default access of PREVENT and all access is logged.

Define access to JES2 system commands defined in the JES2 system commands defined in the table in the IBM JES2 Initialization and Tuning Guide entitled 'JES2 commands with profile names and minimum required authority' is restricted to the appropriate personnel (e.g., operations staff, systems programming personnel, general users).

Define access to specific JES2 system commands is logged as indicated in the table JES2 system commands defined in the table in the IBM JES2 Initialization and Tuning Guide titled "JES2 commands with profile names and minimum required authority".

Assure that elevated access is logged.

Some ACF2 Examples:
$KEY(JES2) TYPE(OPR)
CANCEL.BAT UID(oper) SERVICE(READ,UPDATE) LOG
DISPLAY.JOB UID(*) SERVICE(READ) LOG
START.INITIATOR UID(oper) SERVICE(DELETE) LOG
START.LINE UID(oper) SERVICE(DELETE) LOG 
STOP.INITIATOR UID(oper) SERVICE(DELETE) LOG
STOP.LINE UID(oper) SERVICE(DELETE) LOG 
- UID(*) PREVENT)
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25204r504648_chk'
  tag severity: 'medium'
  tag gid: 'V-223531'
  tag rid: 'SV-223531r533198_rule'
  tag stig_id: 'ACF2-JS-000040'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25192r504649_fix'
  tag 'documentable'
  tag legacy: ['V-97767', 'SV-106871']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
