control 'SV-224245' do
  title 'BMC IOA STC data sets must be properly protected.'
  desc 'BMC IOA STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(IOASTC)

Automated Analysis

Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZIOA0001)

Verify that the accesses to the BMC IOA STC data sets are properly restricted. If the following guidance is true, this is not a finding.

___ The ACF2 data set access authorizations restrict READ access to auditors and BMC users

___ The ACF2 data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set access authorizations restrict UPDATE access to the BMC STCs, batch users and BMC administrators.'
  desc 'fix', "Ensure that WRITE and/or greater access to BMC IOA STC data sets are limited to systems programmers only. UPDATE access can be given to BMC STCs, batch users and BMC administrators. READ access can be given to auditors and BMC users.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged.

The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 

SYS3.IOA.*.IOAO.

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS3)
IOA.-.IOAO.- UID(<syspaudt>) R(A) W(A) A(A) E(A)
IOA.-.IOAO.- UID(<tstcaudt>) R(A) W(A) A(A) E(A)
IOA.-.IOAO.- UID(BMC STCs) R(A) W(A) E(A)
IOA.-.IOAO.- UID(<bmcadmin>)R(A) W(A) E(A)
IOA.-.IOAO.- UID(<audtaudt>)R(A) E(A)   
IOA.-.IOAO.- UID(<bmcuser>) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS BMC IOA for ACF2'
  tag check_id: 'C-25918r868169_chk'
  tag severity: 'medium'
  tag gid: 'V-224245'
  tag rid: 'SV-224245r868171_rule'
  tag stig_id: 'ZIOAA001'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25906r868170_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-31946']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
