control 'SV-224593' do
  title 'BMC CONTROL-O STC data sets must be properly protected.'
  desc 'BMC CONTROL-O STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTOSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTO0001)

Verify that the accesses to the BMC CONTROL-O STC data sets are properly restricted. If the following guidance is true, this is not a finding.

___ The TSS data set access authorizations restrict READ access to auditors, operators, and domain level production control and scheduling personnel.

___ The TSS data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The TSS data set access authorizations restrict UPDATE access to the BMC users and BMC STCs and/or batch users.'
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to BMC CONTROL-O STC data sets are limited to systems programmers only. UPDATE access can be given to BMC users and the BMC STCs and/or batch users. READ access can be given to auditors, operators, and domain level production control and scheduling personnel.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have what type of access and if required which type of access is logged. The installing systems programmer will identify any additional groups requiring access to specific data sets, and once documented the installing systems programmer will work with the ISSO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS3.IOA.*.CTOO.

The following commands are provided as a sample for implementing data set controls: 

TSS PERMIT(<syspaudt>) DSN(SYS3.IOA.*.CTOO.) ACCESS(ALL)
TSS PERMIT(CONTROLO) DSN(SYS3.IOA.*.CTOO.) ACCESS(UPDATE)
TSS PERMIT(<bmcuser>) DSN(SYS3.IOA.*.CTOO.) ACCESS(UPDATE)
TSS PERMIT(<audtaudt>) DSN(SYS3.IOA.*.CTOO.) ACCESS(READ)
TSS PERMIT(<operaudt>) DSN(SYS3.IOA.*.CTOO.) ACCESS(READ)
TSS PERMIT(<pcspaudt>) DSN(SYS3.IOA.*.CTOO.) ACCESS(READ)"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-O for TSS'
  tag check_id: 'C-26276r868682_chk'
  tag severity: 'medium'
  tag gid: 'V-224593'
  tag rid: 'SV-224593r868684_rule'
  tag stig_id: 'ZCTOT001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26264r868683_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-31945']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
