control 'SV-223459' do
  title 'ACF2 PPGM GSO record value must specify protected programs that are only executed by privileged users.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'From the ACF command screen enter:
SET CONTROL(GSO)
LIST LIKE(PPGM-)

Refer to the table of Sensitive Utilities resources and/or generic equivalent as detailed in the table. 

If all applicable programs or their generic equivalent referenced below are represented by GSO PPGM record values, this is not a finding.

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

FDRZAPOP         FDR              Product Internal Modification 

GIMSMP           SMP/E            Change Management Product 

ICKDSF           z/OS             DASD Management 

IDCSC01          z/OS             IDCAMS Set Cache Module 

IEHINITT         z/OS             Tape Management 

IFASMFDP         z/OS SMF         Data Dump Utility 

IND$FILE z/OS                     PC to Mainframe File Transfer
                                  (Applicable only for classified systems) 

CSQJU003         IBM WebSphereMQ
CSQJU004
CSQUCVX
CSQ1LOGP 
CSQUTIL 

WHOIS            z/OS              Share MOD to identify user name from USERID. 
                                   Restricted to data center personnel only.'
  desc 'fix', 'Configure the PPGM GSO value indicating protected programs that are only executed by privileged users in the table below.

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

FDRZAPOP         FDR              Product Internal Modification 

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
                                  Restricted to data center personnel only.

Define protected programs that can only be executed by privileged users.

PGM MASK(pgm mask1, ...,pgm-mask255)

Example:
SET C(GSO)
INSERT PPGM PGM-MASK(<program name or generic equivalent>) 

F ACF2,REFRESH(PPGM)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25132r504504_chk'
  tag severity: 'medium'
  tag gid: 'V-223459'
  tag rid: 'SV-223459r877392_rule'
  tag stig_id: 'ACF2-ES-000390'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25120r504505_fix'
  tag 'documentable'
  tag legacy: ['SV-106719', 'V-97615']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
