control 'SV-223664' do
  title 'IBM Sensitive Utility Controls must be properly defined and protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'If the RACF resource access authorizations for the following sensitive utilities restrict access to the appropriate personnel according to the site security plan, this is not a finding.

If all access for these sensitive utilities is audited, this is not a finding.

Sensitive Utility Controls
Program Product Function 
AHLGTF z/OS System Activity Tracing 
HHLGTF
IHLGTF 

ICPIOCP z/OS System Configuration 
IOPIOCP
IXPIOCP
IYPIOCP
IZPIOCP 

BLSROPTR z/OS Data Management 

DEBE OS/DEBE Data Management 

DITTO OS/DITTO Data Management 

FDRZAPOP FDR Product Internal Modification 

GIMSMP SMP/E Change Management Product 

ICKDSF z/OS DASD Management 

IDCSC01 z/OS IDCAMS Set Cache Module 

IEHINITT z/OS Tape Management 

IFASMFDP z/OS SMF Data Dump Utility 

IND$FILE z/OS PC to Mainframe File Transfer
(Applicable only for classified systems) 

CSQJU003 IBM WebSphereMQ
CSQJU004
CSQUCVX
CSQ1LOGP
CSQUTIL 

WHOIS z/OS Share MOD to identify user name from USERID. 
Restricted to data center personnel only.'
  desc 'fix', "Note: The resources and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.

Ensure that all Sensitive Utility Controls resources and/or generic equivalent are properly protected according to the site security plan.

Use Sensitive Utility Controls table below that lists the resources, access requirements, and logging requirements for Sensitive Utilities, ensuring the following guidelines are followed:

Sensitive Utility Controls
Program Product Function 
AHLGTF z/OS System Activity Tracing 
HHLGTF
IHLGTF 

ICPIOCP z/OS System Configuration 
IOPIOCP
IXPIOCP
IYPIOCP
IZPIOCP 

BLSROPTR z/OS Data Management 

DEBE OS/DEBE Data Management 

DITTO OS/DITTO Data Management 

FDRZAPOP FDR Product Internal Modification 

GIMSMP SMP/E Change Management Product 

ICKDSF z/OS DASD Management 

IDCSC01 z/OS IDCAMS Set Cache Module 

IEHINITT z/OS Tape Management 

IFASMFDP z/OS SMF Data Dump Utility 

IND$FILE z/OS PC to Mainframe File Transfer
 (Applicable only for classified systems) 

CSQJU003 IBM WebSphereMQ
CSQJU004
CSQUCVX
CSQ1LOGP
CSQUTIL 

WHOIS z/OS Share MOD to identify user name from USERID. 
 Restricted to data center personnel only.

The RACF resources as designated in the table above are defined with a default access of NONE.

The RACF resource access authorizations restrict access to the appropriate personnel as designated in the table above.

The RACF resource rules for the resources designated in the table above specify UACC(NONE) and NOWARNING.

The following commands are provided as a sample for implementing resource controls:

RDEF PROGRAM AHLGTF ADDMEM('SYS1.LINKLIB'//NOPADCHK) - 
DATA('ADDED PER SRR PDI RACF0770 ') - 
AUDIT(ALL(READ)) UACC(NONE) OWNER(ADMIN)
PERMIT AHLGTF CLASS(PROGRAM) ID(stcgsmpl)"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25337r868795_chk'
  tag severity: 'medium'
  tag gid: 'V-223664'
  tag rid: 'SV-223664r868797_rule'
  tag stig_id: 'RACF-ES-000160'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25325r868796_fix'
  tag 'documentable'
  tag legacy: ['SV-107137', 'V-98033']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
