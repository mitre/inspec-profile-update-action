control 'SV-224336' do
  title 'ROSCOE Install data sets are not properly protected.'
  desc 'ROSCOE Install data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(ROSRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZROS0000)

b)	Verify that access to the ROSCOE Install data sets are properly restricted.
 
___	The ACF2 data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___	The ACF2 data set rules for the data sets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)	If all of the above are untrue, there is NO FINDING.

d)	If any of the above is true, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that update and allocate access to program product data sets is limited to System Programmers only,  and all update and allocate access is logged. Security Personnel and Auditors should have read access.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

Data sets to be protected will be: 
SYS2.ROSCOE 
SYS2A.ROSCOE 
SYS3.ROSCOE 
SYS3A.ROSCOE

The following commands are provided as a sample for implementing dataset controls: 

$KEY(SYS2)
ROSCOE.- UID(syspaudt) R(A) W(L) A(L) E(A)
ROSCOE.- UID(secaaudt) R(A)  E(A)
ROSCOE.- UID(audtaudt) R(A)  E(A)

$KEY(SYS2A)
ROSCOE.- UID(syspaudt) R(A) W(L) A(L) E(A)
ROSCOE.- UID(secaaudt) R(A)  E(A)
ROSCOE.- UID(audtaudt) R(A)  E(A)

$KEY(SYS3)
ROSCOE.- UID(syspaudt) R(A) W(L) A(L) E(A)
ROSCOE.- UID(secaaudt) R(A)  E(A)
ROSCOE.- UID(audtaudt) R(A)  E(A)

$KEY(SYS3A)
ROSCOE.- UID(syspaudt) R(A) W(L) A(L) E(A)
ROSCOE.- UID(secaaudt) R(A)  E(A)
ROSCOE.- UID(audtaudt) R(A)  E(A)'
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for ACF2'
  tag check_id: 'C-26013r520814_chk'
  tag severity: 'medium'
  tag gid: 'V-224336'
  tag rid: 'SV-224336r855196_rule'
  tag stig_id: 'ZROSA000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26001r520815_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-21879']
  tag cci: ['CCI-002234', 'CCI-000213']
  tag nist: ['AC-6 (9)', 'AC-3']
end
