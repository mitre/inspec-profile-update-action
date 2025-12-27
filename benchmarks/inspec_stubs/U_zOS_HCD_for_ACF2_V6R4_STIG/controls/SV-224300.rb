control 'SV-224300' do
  title 'IBM Hardware Configuration Definition (HCD) User data sets are not properly protected.'
  desc 'IBM Hardware Configuration Definition (HCD) product has the capability to use privileged functions and/or to have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(HCDUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZHCD0002)

b)	Verify that the access to the IBM Hardware Configuration Definition (HCD) install data sets is properly restricted.  The data sets to be protected are the production and working IODF data sets as well as the activity log for the IODF data sets.

Note:	Currently on most CSD systems the prefix for these data sets is SYS3.IODF*.**.

___	The ACF2 data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___	The ACF2 data set rules for the data sets does not restrict READ access to automated operations users and operations personnel.

___	The ACF2 data set rules for the datasets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)	If all of the above are untrue, there is NO FINDING.

d)	If any of the above is true, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that update, and allocate access to program product user data sets is limited to System Programmers and all update and allocate access is logged..  Ensure that read access is limited to auditors, Operations personnel, and Automated Operations users.

The installing System Programmer will identify and document the product user data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

Data sets to be protected will be:

The production IODF data sets.  (i.e. hhhhhhhh.IODFnn)
The working IODF data sets.  (i.e. hhhhhhhh.IODFnn.)
The activity log for the IODF data sets.  (i.e. hhhhhhhh.IODFnn.ACTLOG)

Note:	Currently on most CSD systems the prefix for these data sets is SYS3.IODF*.**.

The following commands are provided as a sample for implementing dataset controls:

SET RULE
$KEY(S3I)
$PREFIX(SYS3)
IODF-.- UID(syspaudt) R(A) W(L) A(L) E(A) DATA(DEFAULT SYSPROG)
IODF-.- UID(tstcaudt) R(A) W(L) A(L) E(A)
IODF-.- UID(audtaudt) R(A) E(A) DATA(DEFAULT Auditor)
IODF-.- UID(autoaudt) R(A) E(A)
IODF-.- UID(operaudt) R(A) E(A)'
  impact 0.5
  ref 'DPMS Target zOS HCD for ACF2'
  tag check_id: 'C-25977r520202_chk'
  tag severity: 'medium'
  tag gid: 'V-224300'
  tag rid: 'SV-224300r520204_rule'
  tag stig_id: 'ZHCDA002'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25965r520203_fix'
  tag 'documentable'
  tag legacy: ['SV-30577', 'V-21592']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
