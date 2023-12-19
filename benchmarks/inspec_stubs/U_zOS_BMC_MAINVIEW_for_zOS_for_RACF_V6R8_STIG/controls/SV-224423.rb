control 'SV-224423' do
  title 'BMC MAINVIEW for z/OS installation data sets are not properly protected.'
  desc 'BMC MAINVIEW for z/OS installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(MVZRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZMVZ0000)

Verify that the accesses to the BMC MAINVIEW for z/OS installation data sets are properly restricted.
 
___	The RACF data set rules for the data sets restricts READ access to all authorized users.

___	The RACF data set rules for the data sets restricts UPDATE and/or ALTER access to systems programming personnel.

___	The RACF data set rules for the data sets specify that all (i.e., failures and successes) UPDATE and/or ALTER access are logged.'
  desc 'fix', "The IAO will ensure that update and alter access to BMC MAINVIEW for z/OS installation data sets is limited to System Programmers only, and all update and alter access is logged.  Read access can be given to all authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and alter access is logged. He will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS2.BMCVIEW.**
SYS3.BMCVIEW.** (data sets that are not altered by product STCs, can be more specific)

The following commands are provided as a sample for implementing data set controls: 

ad 'SYS2.BMCVIEW.**' uacc(none) owner(sys2) -
	audit(success(update) failures(read)) -
	data('BMC MAINVIEW for z/OS Install DS')
pe 'SYS2.BMCVIEW.**' id(<syspaudt> <tstcaudt>) acc(a)
pe 'SYS2.BMCVIEW.**' id(<audtaudt> authorized users) acc(r)
pe 'SYS2.BMCVIEW.**' id(MAINVIEW STCs)

ad 'SYS3.BMCVIEW.**' uacc(none) owner(sys3) -
	audit(success(update) failures(read)) -
	data('BMC MAINVIEW for z/OS Install DS')
pe 'SYS3.BMCVIEW.**' id(<syspaudt> <tstcaudt>) acc(a)
pe 'SYS3.BMCVIEW.**' id(<audtaudt> authorized users) acc(r)
pe 'SYS3.BMCVIEW.**' id(MAINVIEW STCs)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for RACF'
  tag check_id: 'C-26100r518977_chk'
  tag severity: 'medium'
  tag gid: 'V-224423'
  tag rid: 'SV-224423r855093_rule'
  tag stig_id: 'ZMVZR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26088r518978_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-33836']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
