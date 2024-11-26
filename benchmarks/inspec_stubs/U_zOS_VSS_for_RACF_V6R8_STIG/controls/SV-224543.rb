control 'SV-224543' do
  title 'Vanguard Security Solutions (VSS) Install data sets are not properly protected.'
  desc 'Vanguard Security Solutions (VSS) Install data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(VSSRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZVSS0000)

b)	Verify that access to the Vanguard Security Solutions (VSS) Install data sets are properly restricted.
 
___	The RACF data set rules for the product install data sets do not restrict UPDATE and/or ALTER access to systems programming personnel.

___	The RACF data set rules for the product install data sets do not restrict READ access to systems programming personnel, security personnel and auditors.

___	The RACF data set rules for the product install data sets do not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)	If all of the above are untrue, there is NO FINDING.

d)	If any of the above is true, this is a FINDING.'
  desc 'fix', "The IAO will ensure that update and alter access to program product install data sets is limited to System Programmers, and read access is limited to Security personnel and Auditors, and all update and allocate access is logged.

The installing System Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

Data set prefix to be protected will be:

SYS2.VSS.
SYS2A.VSS.
SYS3.VSS.VANOPTS

The following commands are provided as a sample for implementing dataset controls: 

ad 'sys2.vss.**' uacc(none) owner(sys2) -
 audit(success(update) failures(read)) -
 data('Vendor DS Profile: Vanguard Security Solutions')
pe 'sys2.vss.**' id(syspaudt) acc(a)
pe 'sys2.vss.**' id(secaaudt secdaudt audtaudt) acc(r)

ad 'sys2a.vss.**' uacc(none) owner(sys2a) -                  
 audit(success(update) failures(read)) -                        
 data('Vendor Loadlib: Vanguard Security Solutions')
pe 'sys2a.vss.**' id(syspaudt) acc(a) 
pe 'sys2a.vss.**' id(secaaudt secdaudt audtaudt) acc(r)

ad 'sys3.vss.vanopts.**' uacc(none) owner(sys3) -
 audit(success(update) failures(read)) -
 data('Site Customized DS Profile: Vanguard Security Solutions')
pe 'sys3.vss.vanopts.**' id(syspaudt) acc(a)
pe 'sys3.vss.vanopts.**' id(secaaudt secdaudt audtaudt) acc(r)"
  impact 0.5
  ref 'DPMS Target zOS VSS for RACF'
  tag check_id: 'C-26226r520922_chk'
  tag severity: 'medium'
  tag gid: 'V-224543'
  tag rid: 'SV-224543r855219_rule'
  tag stig_id: 'ZVSSR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26214r520923_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-24657']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
