control 'SV-224613' do
  title 'BMC Mainview for z/OS Resource Class must be defined or active in the ACP.'
  desc 'Failure to use a robust ACP to control a product could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', "Refer to the following report produced by the ACP Data Collection:

- TSSCMDS.RPT(#RDT)

If the BMC Mainview for z/OS Resource Class(es) is (are) defined in the Resource Definition Table (RDT) as follows, this is not a finding.

  RESOURCE CLASS = class
   RESOURCE CODE = X'hex code'
       ATTRIBUTE = MASK|NOMASK,MAXOWN(08),MAXPERMIT(044),ACCESS,DEFPROT
          ACCESS = NONE(0000),CONTROL(0400),UPDATE(6000),READ(4000)
          ACCESS = WRITE(2000),ALL(FFFF)
          DEFACC = READ"
  desc 'fix', "The ISSO will ensure the BMC Mainview for z/OS resource class(es) is (are) defined in the TSS RDT.
 
(Note: The RESCLASS and/or RESCODE identified below are examples of a possible installation. The actual RESCLASS and/or RESCODE values are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Use the following commands as an example:

TSS ADDTO(RDT) RESCLASS(BMCVIEW) -
RESCODE(3B) DEFACC(READ) -
ATTR(MASK|NOMASK,DEFPROT,LONG,GENERIC) -
ACLST(NONE,READ,UPDATE,ALL)"
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for TSS'
  tag check_id: 'C-26296r868739_chk'
  tag severity: 'medium'
  tag gid: 'V-224613'
  tag rid: 'SV-224613r868741_rule'
  tag stig_id: 'ZMVZT038'
  tag gtitle: 'SRG-OS-000309'
  tag fix_id: 'F-26284r868740_fix'
  tag 'documentable'
  tag legacy: ['SV-33846', 'V-18011']
  tag cci: ['CCI-000336', 'CCI-002358']
  tag nist: ['CM-4 (2)', 'AC-25']
end
