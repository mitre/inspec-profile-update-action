control 'SV-224581' do
  title 'BMC CONTROL-D STC data sets must be properly protected.'
  desc 'BMC CONTROL-D STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTDSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTD0001)

Verify that the accesses to the BMC CONTROL-D STC data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The TSS data set access authorizations restrict READ access to auditors and CONTROL-D end users.

___ The TSS data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The TSS data set access authorizations restrict WRITE and/or greater access to BMC STCs and/or batch users.

___ The TSS data set access authorizations restrict UPDATE access to centralized and decentralized security personnel.'
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to BMC CONTROL-D STC data sets are limited to systems programmers and BMC STCs and/or batch users. UPDATE access can be given to centralized and decentralized security personnel. READ access can be given to auditors and BMC users.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS3.IOA.*.CTDO.

The following commands are provided as a sample for implementing data set controls: 

TSS PERMIT(syspaudt) DSN(SYS3.IOA.*.CTDO.) ACCESS(ALL)
TSS PERMIT(tstcaudt) DSN(SYS3.IOA.*.CTDO.) ACCESS(ALL)
TSS PERMIT(BMC STCs) DSN(SYS3.IOA.*.CTDO.) ACCESS(ALL)
TSS PERMIT(secaaudt) DSN(SYS3.IOA.*.CTDO.) ACCESS(U)
TSS PERMIT(secdaudt) DSN(SYS3.IOA.*.CTDO.) ACCESS(U)
TSS PERMIT(audtaudt) DSN(SYS3.IOA.*.CTDO.) ACCESS(R)
TSS PERMIT(bmcuser) DSN(SYS3.IOA.*.CTDO.) ACCESS(R)"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-D for TSS'
  tag check_id: 'C-26264r868655_chk'
  tag severity: 'medium'
  tag gid: 'V-224581'
  tag rid: 'SV-224581r868657_rule'
  tag stig_id: 'ZCTDT001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26252r868656_fix'
  tag 'documentable'
  tag legacy: ['SV-32167', 'V-17067']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
