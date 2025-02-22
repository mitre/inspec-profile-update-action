control 'SV-224337' do
  title 'ROSCOE STC data sets are not properly protected.'
  desc 'ROSCOE STC data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(ROSSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZROS0001)

b)	Verify that access to the ROSCOE STC data sets are properly restricted.  The data sets in this group are the data sets identified in the ROSACTxx (if used), ROSLIBxx, and SYSAWSx DD statements of the STC or batch JCL.
 
___	The ACF2 data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___	The ACF2 data set rules for the data sets does not restrict UPDATE and/or ALTER access to the product STC(s) and/or batch job(s).

c)	If all of the above are untrue, there is NO FINDING.

d)	If any of the above is true, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that update and allocate access to the ROSCOE started task or batch job data sets is limited to system programmers and the started task only and all update and allocate access is logged.

The IAO will ensure that all other accesses  to the ROSCOE started task or batch job data sets are properly restricted and all required accesses are properly logged.

Data sets to be protected will be

SYS3.ROSCOE.SYS**
SYS3.ROSCOE.ROSLIB**

Example:

SET RULE
$KEY(SYS3)
ROSCOE.SYS- UID(syspudt) R(A) W(L) A(L) E(A) 
ROSCOE.SYS- UID(stc roscoe) R(A) W(L) A(L) E(A)
ROSCOE.ROSLIB- UID(syspudt) R(A) W(L) A(L) E(A) 
ROSCOE.ROSLIB- UID(stc roscoe) R(A) W(L) A(L) E(A)'
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for ACF2'
  tag check_id: 'C-26014r520817_chk'
  tag severity: 'medium'
  tag gid: 'V-224337'
  tag rid: 'SV-224337r520819_rule'
  tag stig_id: 'ZROSA001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26002r520818_fix'
  tag 'documentable'
  tag legacy: ['SV-21875', 'V-17067']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
