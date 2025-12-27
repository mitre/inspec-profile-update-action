control 'SV-224417' do
  title 'BMC IOA STC data sets must be properly protected.'
  desc 'BMC IOA STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(IOASTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZIOA0001)

Verify that the accesses to the BMC IOA STC data sets are properly restricted. If the following guidance is true, this is not a finding.

___ The RACF data set access authorizations restrict READ access to auditors and BMC users.

___ The RACF data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The RACF data set access authorizations restrict UPDATE access to the BMC STCs,  batch users and BMC administrators.

___ The RACF data set access authorizations specify UACC(NONE) and NOWARNING.'
  desc 'fix', "Ensure that WRITE and/or greater access to BMC IOA STC data sets are limited to systems programmers only. UPDATE access can be given to BMC STCs,  batch users and BMC administrators. READ access can be given to auditors and BMC users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. 

The installing Systems Programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be:
SYS3.IOA.*.IOAO.

The following commands are provided as a sample for implementing data set controls: 

ad 'SYS3.IOA.*.IOAO.**' uacc(none) owner(sys3) -
      audit(failures(read)) -
      data('BMC IOA STC DS')
pe 'SYS3.IOA.*.IOAO.**' id(<syspaudt> <tstcaudt>) acc(a)
pe 'SYS3.IOA.*.IOAO.**' id(BMC STCs <bmcadmin>) acc(u)
pe 'SYS3.IOA.*.IOAO.**' id(<audtaudt> <bmcuser>) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS BMC IOA for RACF'
  tag check_id: 'C-26094r868426_chk'
  tag severity: 'medium'
  tag gid: 'V-224417'
  tag rid: 'SV-224417r868428_rule'
  tag stig_id: 'ZIOAR001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26082r868427_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-31947']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
