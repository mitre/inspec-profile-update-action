control 'SV-224115' do
  title 'BMC CONTROL-M STC data sets will be properly protected.'
  desc 'BMC CONTROL-M STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTMSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTM0001)

Verify that the accesses to the BMC CONTROL-M STC data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The ACF2 data set access authorizations restricts READ access to auditors and BMC users.

___ The ACF2 data set access authorizations restricts WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set access authorizations restricts UPDATE access to the BMC STCs and/or batch users.

___ The ACF2 data set access authorizations restricts UPDATE access to scheduled batch jobs, operations, and production control and scheduling personnel.'
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to BMC CONTROL-M STC data sets are limited to systems programmers only. UPDATE access can be given to scheduled batch jobs, operations, and production control and scheduling personnel, BMC STCs and/or batch users.  READ access can be given to auditors and/or BMC users.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS3.IOA.*.CTMO.

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS3)
IOA.-.CTMO.- UID(<syspaudt>) R(A) W(A) A(A) E(A)
IOA.-.CTMO.- UID(<tstcaudt>) R(A) W(A) A(A) E(A)
IOA.-.CTMO.- UID(CONTDAY) R(A) W(A)  E(A)
IOA.-.CTMO.- UID(CONTROLM) R(A) W(A)  E(A)
IOA.-.CTMO.- UID(<autoaudt>) R(A) W(A)  E(A)
IOA.-.CTMO.- UID(<operaudt>) R(A) W(A)  E(A)
IOA.-.CTMO.- UID(<pcspaudt>) R(A) W(A)  E(A)
IOA.-.CTMO.- UID(<audtaudt>) R(A) E(A)
IOA.-.CTMO.- UID(<bmcuser>) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for ACF2'
  tag check_id: 'C-25788r868133_chk'
  tag severity: 'medium'
  tag gid: 'V-224115'
  tag rid: 'SV-224115r868135_rule'
  tag stig_id: 'ZCTMA001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25776r868134_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-31940']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
