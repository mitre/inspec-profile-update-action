control 'SV-224343' do
  title 'SRRAUDIT User data sets are not properly protected.'
  desc 'SRRAUDIT User data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(SRRUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZSRR0002)

b)	Verify that access to the SRRAUDIT User data sets are properly restricted.

___	The ACF2 data set rules for the data sets does not restrict READ, UPDATE, and/or ALTER access to systems programming personnel, security personnel, and auditors.

___	The ACF2 data set rules for the data sets do not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

b)	If all of the above are untrue, there is NO FINDING.

c)	If any of the above is true, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that read, update, and allocate access to program product user data sets is limited to System Programmers, Security Personnel, and Auditors and all update and allocate access is logged.

The installing System Programmer will identify and document the product user data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

Data set prefix to be protected will be:

SYS3.SRRAUDIT.

If doing a full SRR review using the z/OS STIG Instruction, the following data set prefix to be protected will be:

SYS3.FSO.

The following commands are provided as a sample for implementing dataset controls:

SET RULE
$KEY(S3S)
$PREFIX(SYS3)
SRRAUDIT.- UID(syspaudt) R(A) W(L) A(L) E(A) DATA(DEFAULT SYSPROG)
SRRAUDIT.- UID(secaaudt) R(A) W(L) A(L) E(A) DATA(DEFAULT Security)
SRRAUDIT.- UID(audtaudt) R(A) W(L) A(L) E(A) DATA(DEFAULT Auditor)

$KEY(S3F)
$PREFIX(SYS3)
FSO- UID(syspaudt) R(A) W(L) A(L) E(A) DATA(DEFAULT SYSPROG)
FSO- UID(secaaudt) R(A) W(L) A(L) E(A) DATA(DEFAULT Security)
FSO- UID(audtaudt) R(A) W(L) A(L) E(A) DATA(DEFAULT Auditor)'
  impact 0.5
  ref 'DPMS Target zOS SRRAUDIT for ACF2'
  tag check_id: 'C-26020r520880_chk'
  tag severity: 'medium'
  tag gid: 'V-224343'
  tag rid: 'SV-224343r520882_rule'
  tag stig_id: 'ZSRRA002'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26008r520881_fix'
  tag 'documentable'
  tag legacy: ['SV-23902', 'V-21592']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
