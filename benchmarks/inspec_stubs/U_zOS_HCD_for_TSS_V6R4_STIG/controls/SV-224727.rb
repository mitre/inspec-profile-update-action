control 'SV-224727' do
  title 'IBM Hardware Configuration Definition (HCD) User data sets are not properly protected.'
  desc 'IBM Hardware Configuration Definition (HCD) product has the capability to use privileged functions and/or to have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(HCDUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZHCD0002)

b)	Verify that the access to the IBM Hardware Configuration Definition (HCD) install data sets is properly restricted.  The data sets to be protected are the production and working IODF data sets as well as the activity log for the IODF data sets.

Note:	Currently on most CSD systems the prefix for these data sets is SYS3.IODF*.**.

___	The TSS data set rules for the data sets does not restrict UPDATE and/or ALL access to systems programming personnel.

___	The TSS data set rules for the data sets does not restrict READ access to automated operations users and operations personnel.

___	The TSS data set rules for the data sets do not specify that all (i.e., failures and successes) UPDATE and/or ALL access will be logged.

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

TSS ADD(SYS3) DSN(SYS3)
TSS PER(syspaudt) DSN(SYS3.IODF) ACC(R)
TSS PER(tstcaudt) DSN(SYS3.IODF) ACC(R)
TSS PER(audtaudt) DSN(SYS3.IODF) ACC(R)
TSS PER(autoaudt) DSN(SYS3.IODF) ACC(R)
TSS PER(operaudt) DSN(SYS3.IODF) ACC(R)
TSS PER(syspaudt) DSN(SYS3.IODF) ACC(A) ACTION(AUDIT)
TSS PER(tstcaudt) DSN(SYS3.IODF) ACC(A) ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target zOS HCD for TSS'
  tag check_id: 'C-26418r520220_chk'
  tag severity: 'medium'
  tag gid: 'V-224727'
  tag rid: 'SV-224727r520222_rule'
  tag stig_id: 'ZHCDT002'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26406r520221_fix'
  tag 'documentable'
  tag legacy: ['SV-30599', 'V-21592']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
