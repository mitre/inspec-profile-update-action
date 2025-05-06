control 'SV-224246' do
  title 'BMC IOA User data sets will be properly protected.'
  desc 'BMC IOA User data sets, IOA Core and Repository, have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(IOAUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZIOA0002)

Verify that the accesses to the BMC IOA User data sets are properly restricted. If the following guidance is true, this is not a finding.

___ The ACF2 data set access authorizations restricts READ access to auditors.

___ The ACF2 data set access authorizations restricts WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set access authorizations restricts WRITE and/or greater access to the BMC STCs and/or batch users.

___ The ACF2 data set access authorizations restricts UPDATE access to production control and scheduling personnel and the BMC users.'
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to BMC IOA User data sets are limited to systems programmers and/or BMC STCs and/or batch users only. UPDATE access can be given to production control and scheduling personnel and the BMC users. READ access can be given to auditors.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented  will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS3.IOA.*.IOAC.

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS3)
IOA.-.IOAC.- UID(<syspaudt>) R(A) W(A) A(A) E(A)
IOA.-.IOAC.- UID(<tstcaudt>) R(A) W(A) A(A) E(A)
IOA.-.IOAC.- UID(BMC STCs) R(A) W(A) A(A) E(A)
IOA.-.IOAC.- UID(<bmcuser>) R(A) W(A) E(A)
IOA.-.IOAC.- UID(<pcspaudt>) R(A) W(A) E(A)
IOA.-.IOAC.- UID(<audtaudt>) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS BMC IOA for ACF2'
  tag check_id: 'C-25919r868172_chk'
  tag severity: 'medium'
  tag gid: 'V-224246'
  tag rid: 'SV-224246r868174_rule'
  tag stig_id: 'ZIOAA002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25907r868173_fix'
  tag 'documentable'
  tag legacy: ['SV-32152', 'V-21592']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
