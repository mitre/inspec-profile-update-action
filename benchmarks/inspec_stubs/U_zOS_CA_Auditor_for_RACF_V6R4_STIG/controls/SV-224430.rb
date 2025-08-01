control 'SV-224430' do
  title 'CA Auditor installation data sets are not properly protected.'
  desc 'CA Auditor installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(ADTRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZADT0000)

Verify that the accesses to the CA Auditor installation data sets are properly restricted.
 
___ The RACF data set rules for the data sets restricts READ access to auditors, security administrators, and/or CA Auditor's STCs and batch users.

___ The RACF data set rules for the data sets restricts UPDATE and/or ALTER access to systems programming personnel.

___ The RACF data set rules for the data sets specify that all (i.e., failures and successes) UPDATE and/or ALTER access are logged."
  desc 'fix', "The ISSO will ensure that update and alter access to CA Auditor installation data sets are limited to systems programmers only, and all update and alter access is logged. Read access can be given to auditors, security administrators, and/or CA Auditor's STCs and batch users.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and alter access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS2.EXAMINE
SYS2A.EXAMINE

The following commands are provided as a sample for implementing data set controls: 

ad 'SYS2.EXAMINE.**' uacc(none) owner(sys2) -
	audit(success(update) failures(read)) -
	data('Vendor DS Profile: CA Auditor/Examine')
pe 'SYS2.EXAMINE.**' id(<syspaudt>) acc(a)
pe 'SYS2.EXAMINE.**' id(<audtaudt> <secaaudt> EXAMMON) acc(r)
ad 'SYS2A.EXAMINE.**' uacc(none) owner(sys2a) -
	audit(success(update) failures(read)) -
	data('Vendor DS Profile: CA Auditor/Examine')
pe 'SYS2A.EXAMINE.**' id(<syspaudt>) acc(a)
pe 'SYS2A.EXAMINE.**' id(<audtaudt> <secaaudt> EXAMMON) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS CA Auditor for RACF'
  tag check_id: 'C-26107r868278_chk'
  tag severity: 'medium'
  tag gid: 'V-224430'
  tag rid: 'SV-224430r868280_rule'
  tag stig_id: 'ZADTR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26095r868279_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-31919']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
