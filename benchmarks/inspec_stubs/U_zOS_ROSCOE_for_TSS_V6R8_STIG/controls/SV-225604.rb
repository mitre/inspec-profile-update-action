control 'SV-225604' do
  title 'Resouce Class ROSRES is not defined or active in the ACP.'
  desc 'Failure to use a robust ACP to control a product could potentially compromise the integrity and availability of the MVS operating system and user data.'
  desc 'check', "a)	Refer to the following report produced by the ACP Data Collection:

-	TSSCMDS.RPT(#RDT)

b)	Ensure that Product Resource Class(es) is (are) defined in the Resource Definition Table as follows:

Note: Identify all of the attributes and charactistics of the Product resource class in the TSS Resource Definition Table (delete this note).

  RESOURCE CLASS = ROSRES
   RESOURCE CODE = X'hex code'
       ATTRIBUTE = MASK|NOMASK,MAXOWN(08),MAXPERMIT(044),ACCESS,DEFPROT
          ACCESS = NONE(0000),CONTROL(0400),UPDATE(6000),READ(4000)
          ACCESS = WRITE(2000),ALL(FFFF)
          DEFACC = READ

c)	If all of the items in (b) are true, there is NO FINDING.

d)	If any item in (b) is untrue, this is a FINDING."
  desc 'fix', 'The IAO will ensure the Product resource class(es) is (are) defined in the TSS RDT.  The IAO will issue one of the following commands to define the Product resource class(es):

TSS REPLACE(RDT) RESCLASS(ROSRES) -
  MAXLEN(044) -
  ATTR(MASK|NOMASK,DEFPROT) -
  ACLST(NONE(0000),CONTROL(0400),UPDATE(6000),READ(4000),WRITE(2000),ALL(FFFF)) -
  DEFACC(READ)

TSS ADDTO(RDT) RESCLASS(ROSRES) -
  RESCODE(hex-code) -
  ATTR(MASK|NOMASK,DEFPROT) -
  ACLST(NONE(0000),CONTROL(0400),UPDATE(6000),READ(4000),WRITE(2000),ALL(FFFF)) -
  DEFACC(READ)'
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for TSS'
  tag check_id: 'C-27304r520871_chk'
  tag severity: 'medium'
  tag gid: 'V-225604'
  tag rid: 'SV-225604r855204_rule'
  tag stig_id: 'ZROST038'
  tag gtitle: 'SRG-OS-000309'
  tag fix_id: 'F-27292r520872_fix'
  tag 'documentable'
  tag legacy: ['V-18011', 'SV-24847']
  tag cci: ['CCI-002358']
  tag nist: ['AC-25']
end
