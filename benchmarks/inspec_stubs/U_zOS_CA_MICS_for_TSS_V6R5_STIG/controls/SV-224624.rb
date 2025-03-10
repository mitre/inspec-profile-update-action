control 'SV-224624' do
  title 'CA MICS Resource Management User data sets must be properly protected.'
  desc 'CA MICS Resource Management User data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(MICSRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZMIC0000)

Verify that the accesses to the CA-MICS Resource Management installation data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The TSS data set access authorizations restrict READ access to all authorized users (e.g., auditors, security administrators, and MICS end users).

___ The TSS data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The TSS data set access authorizations restrict WRITE and/or greater access to MICS administrators.

___ The TSS data set access authorizations specify that all (i.e., failures and successes) WRITE and/or greater accesses are logged.'
  desc 'fix', "The ISSO will ensure WRITE and/or greater access to CA MICS Resource Management installation data sets is limited to systems programmers and MICS administrators. READ access can be given to all authorized users (e.g., auditors, security administrators, and MICS end users). All failures and successful WRITE and/or greater accesses are logged. 

The installing systems programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and, if required, that all WRITE and/or greater access is logged. The installing systems programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS2.MICS.

The following commands are provided as a sample for implementing data set controls:

TSS PERMIT(syspaudt) DSN(SYS2.MICS) ACCESS(R)
TSS PERMIT(syspaudt) DSN(SYS2.MICS) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(tstcaudt) DSN(SYS2.MICS) ACCESS(R)
TSS PERMIT(tstcaudt) DSN(SYS2.MICS) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(micsadm) DSN(SYS2.MICS) ACCESS(R)
TSS PERMIT(micsadm) DSN(SYS2.MICS) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(audtaudt) DSN(SYS2.MICS) ACCESS(R)
TSS PERMIT(micsuser) DSN(SYS2.MICS) ACCESS(R)
TSS PERMIT(secaaudt) DSN(SYS2.MICS) ACCESS(R)"
  impact 0.5
  ref 'DPMS Target zOS CA MICS for TSS'
  tag check_id: 'C-26307r868718_chk'
  tag severity: 'medium'
  tag gid: 'V-224624'
  tag rid: 'SV-224624r868720_rule'
  tag stig_id: 'ZMICT000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26295r868719_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-49525']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
