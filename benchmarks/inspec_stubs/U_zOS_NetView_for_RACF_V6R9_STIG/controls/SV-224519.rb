control 'SV-224519' do
  title 'NetView STC data sets are not properly protected.'
  desc 'NetView STC data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(NETVSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZNET0001)

Verify that acess to the NetView STC data sets are properly restricted.

___	The RACF data set rules for the data sets restricts READ access to auditors.

___	The RACF data set rules for the data sets restricts UPDATE and/or ALTER access to systems programming personnel.

___	The RACF data set rules for the data sets restricts UPDATE and/or ALTER access to the product STC(s) and/or batch job(s).'
  desc 'fix', "The IAO will ensure that update and allocate access to NetView STC data sets are limited to System Programmers and NetView STC only, unless a letter justifying access is filed with the IAO. Auditors should have READ access.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS3.NETVIEW.<systemid>.** (VSAM data sets)

The following commands are provided as a sample for implementing dataset controls:

ad 'sys3.netview.<systemid>.<VSAMDS>.**' uacc(none) owner(sys3) -
  audit(success(update) failures(read)) -
  data('netview site VSAM datasets')
pe 'sys3.netview.<systemid>.**' id(audtaudt) acc(r)
pe 'sys3.netview.<systemid>.**' id(CNMPROC syspaudt tstcaudt) acc(a)

The VSAM Dataset required for greater than read access are:
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
SYS3.NETVIEW.<systemid>.SDSIOPEN"
  impact 0.5
  ref 'DPMS Target zOS NetView for RACF'
  tag check_id: 'C-26202r520775_chk'
  tag severity: 'medium'
  tag gid: 'V-224519'
  tag rid: 'SV-224519r520777_rule'
  tag stig_id: 'ZNETR001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26190r520776_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-27322']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
