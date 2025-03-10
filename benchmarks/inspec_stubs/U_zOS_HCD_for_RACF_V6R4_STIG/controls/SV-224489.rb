control 'SV-224489' do
  title 'IBM Hardware Configuration Definition (HCD) install data sets are not properly protected.'
  desc 'IBM Hardware Configuration Definition (HCD) product has the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(HCDRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZHCD0000)

Verify that access to the IBM Hardware Configuration Definition (HCD) install data sets are properly restricted.
 
___	The RACF data set rules for the data sets restricts READ access to auditors, automated operations, operators, and systems programming personnel.

___	The RACF data set rules for the data sets restricts UPDATE and/or ALTER access to systems programming personnel.

___	The RACF data set rules for the data sets specifies that all (i.e., failures and successes) UPDATE and/or ALTER access are logged.'
  desc 'fix', "The IAO will ensure that update and allocate access to IBM Hardware Configuration Definition (HCD) install data sets is limited to System Programmers only, and all update and alter access is logged. Auditors, automated operations, and operators should have READ access.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS1.SCBD*

The following commands are provided as a sample for implementing dataset controls: 

ad 'SYS1.SCBD*.**' uacc(none) owner(sys1) -
	audit(success(update) failures(read)) -
	data('Vendor DS Profile: hcd')
pe 'SYS1.SCBD*.**' id(syspaudt tstcaudt) acc(a)
pe 'SYS1.SCBD*.**' id(audtaudt autoaudt operaudt) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS HCD for RACF'
  tag check_id: 'C-26172r520208_chk'
  tag severity: 'medium'
  tag gid: 'V-224489'
  tag rid: 'SV-224489r855155_rule'
  tag stig_id: 'ZHCDR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26160r520209_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-30545']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
