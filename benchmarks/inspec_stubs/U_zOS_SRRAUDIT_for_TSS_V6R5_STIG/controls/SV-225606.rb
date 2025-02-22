control 'SV-225606' do
  title 'SRRAUDIT installation data sets must be properly protected.'
  desc 'SRRAUDIT installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(SRRPROD)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZSRR0000)

Verify that the accesses to the SRRAUDIT installation data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The TSS data set access authorizations restricts READ access to systems programming personnel, domain level production control and scheduling personnel, security personnel, and auditors.

___ The TSS data set access authorizations restricts WRITE and/or greater access to systems programming personnel.

___ The TSS data set access authorizations specify that all (i.e., failures and successes) WRITE and/or greater accesses are logged.'
  desc 'fix', "The ISSO will ensure WRITE and/or greater access to SRRAUDIT installation data sets is limited to systems programmers only, and all WRITE and/or greater access is logged. All failures and successful WRITE and/or greater accesses are logged.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and, if required, that all WRITE and/or greater accesses are logged. The installing systems programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS2.SRRAUDIT.

The following commands are provided as a sample for implementing data set controls:

TSS PERMIT(syspaudt) DSN(SYS2.SRRAUDIT.) ACCESS(R)
TSS PERMIT(syspaudt) DSN(SYS2.SRRAUDIT.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(tstcaudt) DSN(SYS2.SRRAUDIT.) ACCESS(R)
TSS PERMIT(tstcaudt) DSN(SYS2.SRRAUDIT.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(audtaudt) DSN(SYS2.SRRAUDIT.) ACCESS(R)
TSS PERMIT(pcspaudt) DSN(SYS2.SRRAUDIT.) ACCESS(R)
TSS PERMIT(secaaudt) DSN(SYS2.SRRAUDIT.) ACCESS(R)"
  impact 0.5
  ref 'DPMS Target zOS SRRAUDIT for TSS'
  tag check_id: 'C-27306r868757_chk'
  tag severity: 'medium'
  tag gid: 'V-225606'
  tag rid: 'SV-225606r868759_rule'
  tag stig_id: 'ZSRRT000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27294r868758_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-21731']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
