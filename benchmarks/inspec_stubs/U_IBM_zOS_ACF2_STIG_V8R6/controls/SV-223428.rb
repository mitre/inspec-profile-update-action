control 'SV-223428' do
  title 'IBM z/OS Sensitive Utility Controls must be properly defined and protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer to the table of Sensitive Utilities resources and/or generic equivalent as detailed in the table. 

If the ACF2 resources are defined with a default access of PREVENT, this is not a finding.

If the ACF2 resource access authorizations restrict access to the appropriate personnel according to the site security plan, this not a finding.

If the ACF2 resource logging is correctly specified, this is not a finding.

Sensitive Utility Controls
Program          Product          Function 
AHLGTF           z/OS             System Activity Tracing 
HHLGTF
IHLGTF 

ICPIOCP          z/OS             System Configuration 
IOPIOCP
IXPIOCP
IYPIOCP
IZPIOCP 

BLSROPTR         z/OS             Data Management 

DEBE             OS/DEBE          Data Management 

DITTO            OS/DITTO         Data Management 

FDRZAPOP         FDR Product      Internal Modification 

GIMSMP           SMP/E            Change Management Product 

ICKDSF           z/OS             DASD Management 

IDCSC01          z/OS             IDCAMS Set Cache Module 

IEHINITT         z/OS             Tape Management 

IFASMFDP         z/OS SMF         Data Dump Utility 

IND$FILE         z/OS             PC to Mainframe File Transfer
                                  (Applicable only for classified systems) 

CSQJU003         IBM WebSphereMQ
CSQJU004
CSQUCVX
CSQ1LOGP 
CSQUTIL 

WHOIS            z/OS             Share MOD to identify user name from USERID. 
                                  Restricted to data center personnel only.'
  desc 'fix', 'Refer to the Site Security plan for Sensitive Programs/Utilities for lists the resources, access requirements, and logging requirements for Sensitive Utilities.

Configure ACF2 resources to be defined with a default access of PREVENT.

Configure ACF2 resource access authorizations to restrict access to the appropriate personnel.

Configure ACF2 resource logging to be correctly specified.

The following commands are provided as a sample for implementing resource controls:

$KEY(AHLGTF) TYPE(PGM)
UID(stcg) LOG
UID(*) PREVENT

F ACF2,REBUILD(PGM)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25101r504422_chk'
  tag severity: 'medium'
  tag gid: 'V-223428'
  tag rid: 'SV-223428r533198_rule'
  tag stig_id: 'ACF2-ES-000070'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25089r504423_fix'
  tag 'documentable'
  tag legacy: ['SV-106657', 'V-97553']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
