control 'SV-224544' do
  title 'Vanguard Security Solutions (VSS) User data sets are not properly protected.'
  desc 'Vanguard Security Solutions (VSS) User data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)       Refer to the following report produced by the Data Set and Resource Data Collection:

-       SENSITVE.RPT(VSSUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-       PDI(ZVSS0002)

b)       Verify that access to the Vanguard Security Solutions (VSS) User data sets are properly restricted.

___       The RACF data set rules for the product user data sets do not restrict READ, UPDATE, and/or ALTER access to systems programming personnel, security personnel, and auditors.

___       The RACF data set rules for the product user data sets do not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)       If all of the above are untrue, there is NO FINDING.

d)       If any of the above is true, this is a FINDING.'
  desc 'fix', "The IAO will ensure that read, update, and alter access to program product user data sets is limited to System Programmers, Security Personnel, and Auditors and all update and alter access is logged.

The installing System Programmer will identify and document the product user data sets and categorize them according to who will have update and alter access and if required that all update and alter access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

Data set prefix to be protected will be:

SYS3.VSS.

The above prefix can specify specific data sets, these would include the VSAM and JCL data sets.  The following commands are provided as a sample for implementing dataset controls: 

ad 'sys3.vss.**' uacc(none) owner(sys3) -                  
 audit(success(update) failures(read)) -                        
 data('Site Customized DS Profile: Vanguard Security Solutions')
pe 'sys3.vss.**' id(syspaudt secaaudt audtaudt) acc(a)"
  impact 0.5
  ref 'DPMS Target zOS VSS for RACF'
  tag check_id: 'C-26227r520925_chk'
  tag severity: 'medium'
  tag gid: 'V-224544'
  tag rid: 'SV-224544r520927_rule'
  tag stig_id: 'ZVSSR002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26215r520926_fix'
  tag 'documentable'
  tag legacy: ['SV-24915', 'V-21592']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
