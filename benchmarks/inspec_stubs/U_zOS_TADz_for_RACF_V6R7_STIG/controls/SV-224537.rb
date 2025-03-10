control 'SV-224537' do
  title 'Tivoli Asset Discovery for z/OS (TADz) Install data sets are not properly protected.'
  desc 'Tivoli Asset Discovery for z/OS (TADz) Install data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(TADZRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZTAD0000)

b)	Verify that access to the TADz Install data set are properly restricted.
 
___	The RACF data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___	The RACF data set rules for the data sets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)	If all of the above are untrue, there is NO FINDING.

d)	If any of the above is true, this is a FINDING.'
  desc 'fix', "The IAO will ensure that update and alter access to program product data sets is limited to System Programmers and all update and allocate access is logged.  Auditors should have read access.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and alter access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

Data set prefix to be protected will be:

SYS2.TADZ.
SYS2.TADZ.*.SHSIMOD1.** (optional fully-qualified APF).
SYS3.TADZ.

The following commands are provided as a sample for implementing dataset controls: 

ad 'sys2.TADZ.**' uacc(none) owner(sys2) -
 audit(success(update) failures(read)) -
 data('Vendor DS Profile: TADZ')
pe 'sys2.TADZ.**' id(syspaudt) acc(a)
pe 'sys2.tadz.**' id(audtaudt) 
ad 'sys2.tadz.*.shsimod1.**' uacc(none) owner(sys2) -     
 audit(success(update) failures(read)) -                  
 data('Vendor DS Profile: Tivoli Asset Discovery APF DS') 
pe 'sys2.tadz.*.shsimod1.**' id(syspaudt) acc(a) 
pe 'sys2.tadz.*.shsimod1.**' id(audtaudt)      
ad 'sys3.TADZ.**' uacc(none) owner(sys3) -
 audit(success(update) failures(read)) -
 data('TADZ Vendor Datasets')
pe 'sys3.TADZ.**' id(syspaudt) acc(a)
pe 'sys3.tadz.**' id(audtaudt)
setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS TADz for RACF'
  tag check_id: 'C-26220r520898_chk'
  tag severity: 'medium'
  tag gid: 'V-224537'
  tag rid: 'SV-224537r855214_rule'
  tag stig_id: 'ZTADR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26208r520899_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-28470']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
