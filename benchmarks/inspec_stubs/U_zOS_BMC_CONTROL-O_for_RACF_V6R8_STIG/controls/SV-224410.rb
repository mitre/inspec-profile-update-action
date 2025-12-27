control 'SV-224410' do
  title 'BMC CONTROL-O installation data sets will be properly protected.'
  desc 'BMC CONTROL-O installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTORPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTO0000)

Verify that the accesses to the BMC CONTROL-O installation data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The RACF data set rules for the data sets restricts READ access to auditors, BMC users, and BMC STCs and/or batch users.

___ The RACF data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

___ The RACF data set rules for the data sets specify that all (i.e., failures and successes) WRITE and/or greater access are logged.

___ The RACF data set rules for the data sets specify UACC(NONE) and NOWARNING.'
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to BMC CONTROL-O installation data sets are limited to systems programmers only, and all WRITE and/or greater access is logged. READ access can be given to auditors, BMC users, and BMC STCs and/or batch users. All failures and successful WRITE and/or greater accesses are logged.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS2.IOA.*.CTOI.

The following commands are provided as a sample for implementing data set controls: 

ad 'SYS2.IOA.*.CTOI.**' uacc(none) owner(sys2) -
	audit(success(update) failures(read)) -
	data('Vendor DS Profile: BMC CONTROL-O')
pe 'SYS2.IOA.*.CTOI.**' id(<syspaudt>) acc(a)
pe 'SYS2.IOA.*.CTOI.**' id(<audtaudt> <bmcuser>) acc(r)
pe 'SYS2.IOA.*.CTOI.**' id(CONTROLO) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-O for RACF'
  tag check_id: 'C-26087r868375_chk'
  tag severity: 'medium'
  tag gid: 'V-224410'
  tag rid: 'SV-224410r868378_rule'
  tag stig_id: 'ZCTOR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26075r868376_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-31908']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
