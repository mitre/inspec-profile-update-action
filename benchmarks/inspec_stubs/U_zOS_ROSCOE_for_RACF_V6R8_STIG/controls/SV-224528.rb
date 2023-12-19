control 'SV-224528' do
  title 'ROSCOE Install data sets are not properly protected.'
  desc 'ROSCOE Install data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(ROSRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZROS0000)

b)	Verify that access to the ROSCOE Install data set are properly restricted.
 
___	The RACF data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___	The RACF data set rules for the data sets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)	If all of the above are untrue, there is NO FINDING.

d)	If any of the above is true, this is a FINDING.'
  desc 'fix', "The IAO will ensure that update and alter access to program product data sets is limited to System Programmers, Security Personnel and Auditors only,  and all update and allocate access is logged.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and alter access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

Data set prefix to be protected will be:

SYS2.ROSCOE.
SYS2A.ROSCOE.
SYS3.ROSCOE.
SYS3A.ROSCOE.

The following commands are provided as a sample for implementing dataset controls: 

ad 'sys2.roscoe.**' uacc(none) owner(sys2) -
	audit(success(update) failures(read)) -
	data('Vendor DS Profile: ROSCOE')
pe 'sys2.roscoe.**' id(syspaudt) acc(a)
pe 'sys2.roscoe.**' id(*) acc(r)
ad 'sys2a.roscoe.**' uacc(none) owner(sys2a) -
	audit(success(update) failures(read)) -
	data('Roscoe Vendor Datasets')
pe 'sys2a.roscoe.**' id(<syspaudt>) acc(a)
pe 'sys2a.roscoe.**' id(*) acc(r)
ad 'sys3.roscoe.**' uacc(none) owner(sys3) -
	audit(success(update) failures(read)) -
	data('Roscoe Vendor Datasets')
pe 'sys3.roscoe.**' id(<syspaudt>) acc(a)
pe 'sys3.roscoe.**' id(*) acc(r)
ad 'sys3a.roscoe.**' uacc(none) owner(sys3a) -
	audit(success(update) failures(read)) -
	data('Roscoe Vendor Datasets')
pe 'sys3a.roscoe.**' id(<syspaudt>) acc(a)
pe 'sys3a.roscoe.**' id(*) acc(r)
setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for RACF'
  tag check_id: 'C-26211r520832_chk'
  tag severity: 'medium'
  tag gid: 'V-224528'
  tag rid: 'SV-224528r855199_rule'
  tag stig_id: 'ZROSR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26199r520833_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-21927']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
