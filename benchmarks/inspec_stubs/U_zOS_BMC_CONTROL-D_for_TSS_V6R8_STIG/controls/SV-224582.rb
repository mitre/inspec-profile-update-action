control 'SV-224582' do
  title 'BMC CONTROL-D user data sets must be properly protected.'
  desc 'BMC CONTROL-D User data sets, CDAM and Repository, have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTMUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTD0002)

Verify that the accesses to the BMC CONTROL-D User data sets are properly restricted. If the following guidance is true, this is not a finding.

___ The TSS data set access authorizations restrict READ access to auditors.

___ The TSS data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The TSS data set access authorizations restrict WRITE and/or greater access to the BMC CONTROL-D's STC(s) and/or batch user(s).

___ The TSS data set access authorizations restrict UPDATE access to centralized and decentralized security personnel, and/or CONTROL-D end users."
  desc 'fix', "The ISSO must ensure that WRITE and/or greater access to BMC CONTROL-D User data sets are limited to systems programmers and BMC STCs and/or batch users. Additionally, UPDATE access can be given to centralized and decentralized security personnel, and BMC users. READ access can be given to auditors.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS3.IOA.*.CTDR.
CTRUSR.
CTDSRV.
CTDJB1.

The following commands are provided as a sample for implementing data set controls: 

TSS PERMIT(syspaudt) DSN(SYS3.IOA.*.CTDR.) ACCESS(ALL)
TSS PERMIT(tstcaudt) DSN(SYS3.IOA.*.CTDR.) ACCESS(ALL)
TSS PERMIT(BMC STCs) DSN(SYS3.IOA.*.CTDR.) ACCESS(ALL)
TSS PERMIT(bmcuser) DSN(SYS3.IOA.*.CTDR.) ACCESS(U)
TSS PERMIT(secaaudt) DSN(SYS3.IOA.*.CTDR.) ACCESS(U)
TSS PERMIT(secdaudt) DSN(SYS3.IOA.*.CTDR.) ACCESS(U)
TSS PERMIT(audtaudt) DSN(SYS3.IOA.*.CTDR.) ACCESS(R)

TSS PERMIT(syspaudt) DSN(CTRUSR.) ACCESS(ALL)
TSS PERMIT(tstcaudt) DSN(CTRUSR.) ACCESS(ALL)
TSS PERMIT(BMC STCs) DSN(CTRUSR.) ACCESS(ALL)
TSS PERMIT(bmcuser) DSN(CTRUSR.) ACCESS(U)
TSS PERMIT(secaaudt) DSN(CTRUSR.) ACCESS(U)
TSS PERMIT(secdaudt) DSN(CTRUSR.) ACCESS(U)
TSS PERMIT(audtaudt) DSN(CTRUSR.) ACCESS(R)

TSS PERMIT(syspaudt) DSN(CTDSRV.) ACCESS(ALL)
TSS PERMIT(tstcaudt) DSN(CTDSRV.) ACCESS(ALL)
TSS PERMIT(BMC STCs) DSN(CTDSRV.) ACCESS(ALL)
TSS PERMIT(bmcuser) DSN(CTDSRV.) ACCESS(U)
TSS PERMIT(secaaudt) DSN(CTDSRV.) ACCESS(U)
TSS PERMIT(secdaudt) DSN(CTDSRV.) ACCESS(U)
TSS PERMIT(audtaudt) DSN(CTDSRV.) ACCESS(R)

TSS PERMIT(syspaudt) DSN(CTDJB1.) ACCESS(ALL)
TSS PERMIT(tstcaudt) DSN(CTDJB1.) ACCESS(ALL)
TSS PERMIT(BMC STCs) DSN(CTDJB1.) ACCESS(ALL)
TSS PERMIT(bmcuser) DSN(CTDJB1.) ACCESS(U)
TSS PERMIT(secaaudt) DSN(CTDJB1.) ACCESS(U)
TSS PERMIT(secdaudt) DSN(CTDJB1.) ACCESS(U)
TSS PERMIT(audtaudt) DSN(CTDJB1.) ACCESS(R)"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-D for TSS'
  tag check_id: 'C-26265r868658_chk'
  tag severity: 'medium'
  tag gid: 'V-224582'
  tag rid: 'SV-224582r868660_rule'
  tag stig_id: 'ZCTDT002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26253r868659_fix'
  tag 'documentable'
  tag legacy: ['V-21592', 'SV-32164']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
