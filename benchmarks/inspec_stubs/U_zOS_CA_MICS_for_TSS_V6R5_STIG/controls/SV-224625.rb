control 'SV-224625' do
  title 'CA MICS Resource Management User data sets must be properly protected.'
  desc 'CA MICS Resource Management User datasets contain sensitive data obtained through the MICS data collection process. Failure to properly identify and restrict access to these data sets could result in unauthorized access to sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(MICSUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZMIC0002)

Verify that the accesses to the CA MICS Resource Management User data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The TSS data set access authorizations restrict READ access to all authorized users (e.g., auditors, security administrators, and MICS end users).

___ The TSS data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The TSS data set access authorizations restrict WRITE and/or greater access to SMF Batch user(s) and MICS Administrators.

___ The TSS data set access authorizations restrict WRITE and/or greater access to SMF Batch user(s) and MICS Administrators.'
  desc 'fix', "The ISSO will ensure WRITE and/or greater access to CA MICS Resource Management User data sets is limited to SMF Batch user(s), MICS Administrators, and systems programming personnel. READ access can be given to all authorized users (e.g., auditors, security administrators, and MICS end users).

The installing systems programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and, if required, that all WRITE and/or greater access is logged. The installing systems programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be (additional data sets may be required):
SYS2.MICS.DATA.

The following commands are provided as a sample for implementing data set controls:

TSS PERMIT(syspaudt) DSN(SYS2.MICS.DATA.) ACCESS(ALL)
TSS PERMIT(tstcaudt) DSN(SYS2.MICS.DATA.) ACCESS(ALL)
TSS PERMIT(micsadm) DSN(SYS2.MICS.DATA.) ACCESS(ALL)
TSS PERMIT(smfbaudt) DSN(SYS2.MICS.DATA.) ACCESS(ALL)
TSS PERMIT(audtaudt) DSN(SYS2.MICS.DATA.) ACCESS(R)
TSS PERMIT(micsuser) DSN(SYS2.MICS.DATA.) ACCESS(R)
TSS PERMIT(secaaudt) DSN(SYS2.MICS.DATA.) ACCESS(R)"
  impact 0.5
  ref 'DPMS Target zOS CA MICS for TSS'
  tag check_id: 'C-26308r868721_chk'
  tag severity: 'medium'
  tag gid: 'V-224625'
  tag rid: 'SV-224625r868723_rule'
  tag stig_id: 'ZMICT002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26296r868722_fix'
  tag 'documentable'
  tag legacy: ['SV-50082', 'V-21592']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
