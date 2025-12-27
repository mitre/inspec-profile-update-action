control 'SV-223930' do
  title 'IBM z/OS Sensitive Utility Controls must be properly defined and protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer to the table of Sensitive Utilities resources and/or generic equivalent as detail in the table below.

If the TSS resource access authorizations for the following sensitive utilities restrict access to the appropriate personnel, this is not a finding.

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

If the TSS resources are owned or DEFPROT is specified for the resource class, this is not a finding.

If the TSS resource logging is correctly specified, this is not a finding.'
  desc 'fix', "Ensure that the following are properly specified in the ACP.

Note: The resources and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.

Ensure that all Sensitive Utility Controls resources and/or generic equivalent are properly protected according to the requirements specified in Sensitive Utility Controls table below. This table lists the resources, access requirements, and logging requirements for Sensitive Utilities, ensures the following guidelines are followed:

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

The TSS resources as designated in the above table are owned and/or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(dept-acid) PROGRAM(AHLGTF)
TSS PERMIT(stcgsmpl) PROGRAM(AHLGTF) ACTION(AUDIT)"
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25603r868953_chk'
  tag severity: 'medium'
  tag gid: 'V-223930'
  tag rid: 'SV-223930r868955_rule'
  tag stig_id: 'TSS0-ES-000570'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25591r868954_fix'
  tag 'documentable'
  tag legacy: ['SV-107671', 'V-98567']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
