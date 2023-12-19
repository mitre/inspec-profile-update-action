control 'SV-224329' do
  title 'NetView STC data sets are not properly protected.'
  desc 'NetView STC data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(NETVSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZNET0001)

Verify that acess to the NetView STC data sets are properly restricted.

___	The ACF2 data set rules for the data sets restricts READ access to auditors.

___	The ACF2 data set rules for the data sets restricts UPDATE and/or ALTER access to systems programming personnel.

___	The ACF2 data set rules for the data sets restrictS UPDATE and/or ALTER access to the product STC(s) and/or batch job(s).'
  desc 'fix', 'The IAO will ensure that update and allocate access to NetView STC data sets are limited to System Programmers and NetView STC only, unless a letter justifying access is filed with the IAO. Auditors should have READ access.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS3.NETVIEW.<SYSTEMID>.- (VSAM data sets)

The following commands are provided as a sample for implementing dataset controls: 

SET RULE
$KEY(SYS3) 
NETVIEW.<systemid>.- UID(audtaudt) R(A) E(A)
NETVIEW.<systemid>.- UID(cnmproc) R(A) W(A) A(A) E(A)
NETVIEW.<systemid>.- UID(syspudt) R(A) W(A) A(A) E(A)
NETVIEW.<systemid>.- UID(tstcaudt) R(A) W(A) A(A) E(A)

The VSAM dataset required for greater than read access are:
SYS3.NETVIEW.<systemid>.AAUVSPL
SYS3.NETVIEW.<systemid>.AAUVSSL
SYS3.NETVIEW.<systemid>.BNJLGPR
SYS3.NETVIEW.<systemid>.BNJLGSE
SYS3.NETVIEW.<systemid>.BNJ36PR
SYS3.NETVIEW.<systemid>.BNJ36SE
SYS3.NETVIEW.<systemid>.DSIKPNL
SYS3.NETVIEW.<systemid>.DSILIST
SYS3.NETVIEW.<systemid>.DSILOGP
SYS3.NETVIEW.<systemid>.DSILOGS
SYS3.NETVIEW.<systemid>.DSISVRT
SYS3.NETVIEW.<systemid>.DSITRCP
SYS3.NETVIEW.<systemid>.DSITRCS
SYS3.NETVIEW.<systemid>.SDSIOPEN'
  impact 0.5
  ref 'DPMS Target zOS NetView for ACF2'
  tag check_id: 'C-26006r520760_chk'
  tag severity: 'medium'
  tag gid: 'V-224329'
  tag rid: 'SV-224329r520762_rule'
  tag stig_id: 'ZNETA001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25994r520761_fix'
  tag 'documentable'
  tag legacy: ['SV-27316', 'V-17067']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
