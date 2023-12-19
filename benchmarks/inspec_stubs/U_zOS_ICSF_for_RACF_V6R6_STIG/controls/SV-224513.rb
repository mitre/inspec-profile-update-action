control 'SV-224513' do
  title 'IBM Integrated Crypto Service Facility (ICSF) install data sets are not properly protected.'
  desc 'IBM Integrated Crypto Service Facility (ICSF) product has the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(ICSFRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZICS0000)

b)	Verify that access to the IBM Integrated Crypto Service Facility (ICSF) install data sets are properly restricted.
 
___	The RACF data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___	The RACF data set rules for the data sets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)	If all of the above are untrue, there is NO FINDING.

d)	If any of the above is true, this is a FINDING.'
  desc 'fix', "The IAO will ensure that update and allocate access to IBM Integrated Crypto Service Facility (ICSF) install data sets is limited to System Programmers only, and all update and allocate access is logged. Read access can be given to Auditors and any other users that have a valid requirement to utilize these data sets.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged.  He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS1.CSF

The following commands are provided as a sample for implementing data set controls: 

ad 'SYS1.CSF.**' uacc(none) owner(sys1) -
	audit(success(update) failures(read)) -
	data('Vendor DS Profile: icsf')
pe 'SYS1.CSF.**' id(syspaudt tstcaudt) acc(a)
pe 'SYS1.CSF.**' id(icsfusrs) acc(r)

ad 'sys1.csf.scsfmod0.**' owner(sys1) 
 data('apf auth icsf ds') -
 audit(success(update) failures(read)) uacc(none)               
pe 'sys1.csf.scsfmod0.**' id(syspaudt tstcaudt) acc(a)                    

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS ICSF for RACF'
  tag check_id: 'C-26196r520400_chk'
  tag severity: 'medium'
  tag gid: 'V-224513'
  tag rid: 'SV-224513r520402_rule'
  tag stig_id: 'ZICSR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26184r520401_fix'
  tag 'documentable'
  tag legacy: ['SV-30549', 'V-16932']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
