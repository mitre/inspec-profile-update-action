control 'SV-224308' do
  title 'ACF2/CICS parameter data sets are not protected in accordance with the proper security requirements.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. Unauthorized access to ACF2/CICS parameter data sets (i.e., product, security) could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the ACF2 Data Collection:

-	SENSITVE.RPT(CICSRPT)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b)	UPDATE and/or ALLOCATE access to the ACF2/CICS parameter data set, specified on the ACF2PARM DD statement, is restricted to systems programming personnel and security personnel.

c)	If all items in (b) are true, there is NO FINDING.

d)	If any item in (b) is untrue, this is a FINDING.'
  desc 'fix', "The IAO will ensure that update and allocate access to the ACF2/CICS parameter data set is limited to system programmers and security personnel.

Review the access authorizations for CICS system data sets.

UPDATE and/or ALLOCATE access to the ACF2/CICS parameter data set, specified on the ACF2PARM DD statement, is restricted to systems programming personnel and security personnel.

Example:

$KEY(S3C)    
$PREFIX(SYS3)
CICSTS.SYSIN    UID(syspaudt) R(A)  W(L) A(L)  E(A)
CICSTS.SYSIN    UID(secaaudt) R(A)  W(L) A(L)  E(A)
CICSTS.SYSIN    UID(*) PREVENT

SET RULE
COMPILE 'ACF2.MVA.DSNRULES(S3C)' STORE"
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for ACF2'
  tag check_id: 'C-25985r520244_chk'
  tag severity: 'medium'
  tag gid: 'V-224308'
  tag rid: 'SV-224308r520246_rule'
  tag stig_id: 'ZCICA011'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25973r520245_fix'
  tag 'documentable'
  tag legacy: ['SV-7475', 'V-7091']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
