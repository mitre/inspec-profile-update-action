control 'SV-224518' do
  title 'NetView install data sets are not properly protected.'
  desc 'NetView Install data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(NETVRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZNET0000)

b)	Verify that access to the NetView install data sets are properly restricted.
 
___	The RACF data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___	The RACF data set rules for the datasets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)	If all of the above are untrue, there is NO FINDING.

d)	If any of the above is true, this is a FINDING.'
  desc 'fix', "The IAO will ensure that update and allocate access to NetView install data sets is limited to System Programmers only and all update and allocate access is logged. Auditors should be granted READ access.  

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

Data sets to be protected will be: 
SYS2.NETVIEW 
SYS2A.NETVIEW
SYS3.NETVIEW

ad 'sys2.netview.**' uacc(none) owner(sys2) -
audit(success(update) failures(read))
pe 'sys2.netview.**' id(syspaudt) acc(a)
pe 'sys2.netview.**' id(audtaudt)
ad 'sys2a.netview.**' uacc(none) owner(sys2a) -
audit(success(update) failures(read))
pe 'sys2a.netview.**' id(syspaudt) acc(a)
pe 'sys2a.netview.**' id(audtaudt)
ad 'sys3.netview.**' uacc(none) owner(sys3) - 
audit(success(update) failures(read))
pe 'sys3.netview.**' id(syspaudt) acc(a)
pe 'sys3.netvidew.**' id(audtaudt)"
  impact 0.5
  ref 'DPMS Target zOS NetView for RACF'
  tag check_id: 'C-26201r520772_chk'
  tag severity: 'medium'
  tag gid: 'V-224518'
  tag rid: 'SV-224518r855185_rule'
  tag stig_id: 'ZNETR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26189r520773_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-27314']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
