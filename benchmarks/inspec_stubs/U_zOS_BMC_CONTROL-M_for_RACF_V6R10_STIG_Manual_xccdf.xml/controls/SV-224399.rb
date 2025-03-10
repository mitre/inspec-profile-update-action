control 'SV-224399' do
  title 'BMC CONTROL-M User data sets will be properly protected.'
  desc 'BMC CONTROL-M User data sets, Repository, have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTMUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTM0002)

Verify that the accesses to the BMC CONTROL-M User data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The RACF data set access authorizations restrict READ access to auditors.

___ The RACF data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The RACF data set access authorizations restrict WRITE and/or greater access to the BMC STCs and/or batch users.

___ The RACF data set access authorizations restrict UPDATE access to the BMC Users, operations, and production control and scheduling personnel (both domain level and Application level).

___ The RACF data set rules for the data sets specify UACC(NONE) and NOWARNING.'
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to BMC CONTROL-M User data sets are limited to systems programmers and/or BMC STCs and/or batch users only. UPDATE access can be given to the BMC Users, operations, and production control and scheduling personnel (both domain level and Application level). READ access can be given to auditors.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS3.IOA.*.CTMC.

The following commands are provided as a sample for implementing data set controls: 

ad 'SYS3.IOA.*.CTMC.**' uacc(none) owner(sys3) -
	audit(failures(read)) -
	data('ControlM Repository Dataset')
pe 'SYS3.IOA.*.CTMC.**' id(<syspaudt>) acc(a)
pe 'SYS3.IOA.*.CTMC.**' id(BMC STCs) acc(a)
pe 'SYS3.IOA.*.CTMC.**' id(<bmcuser> <operaudt> <pcspaudt> <dpcsaudt>) acc(u)
pe 'SYS3.IOA.*.CTMC.**' id(<audtaudt>) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for RACF'
  tag check_id: 'C-26076r868360_chk'
  tag severity: 'medium'
  tag gid: 'V-224399'
  tag rid: 'SV-224399r868362_rule'
  tag stig_id: 'ZCTMR002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26064r868361_fix'
  tag 'documentable'
  tag legacy: ['SV-32160', 'V-21592']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
