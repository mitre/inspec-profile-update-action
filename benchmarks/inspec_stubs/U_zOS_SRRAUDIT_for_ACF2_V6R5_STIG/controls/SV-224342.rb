control 'SV-224342' do
  title 'SRRAUDIT installation data sets must be properly protected.'
  desc 'SRRAUDIT installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(SRRPROD)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZSRR0000)

Verify that the accesses to the SRRAUDIT installation data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The ACF2 data set rules for the data sets do not restrict READ access to systems programming personnel, domain level production control and scheduling personnel, security personnel, and auditors.

___ The ACF2 data set rules for the data sets do not restrict WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set rules for the data sets do not specify that all (i.e., failures and successes) WRITE and/or greater access will be logged.'
  desc 'fix', "The ISSO will ensure WRITE and/or greater access to SRRAUDIT installation data sets is limited to systems programmers only, and all WRITE and/or greater access is logged. READ access can be given to Security personnel, Production Control and Scheduling personnel, and Auditors. All failures and successful WRITE and/or greater accesses are logged.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and, if required, that all WRITE and/or greater accesses are logged. The installing systems programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS2.SRRAUDIT.

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS2)
SET RULE
$KEY(S2S)
$PREFIX(SYS2)
SRRAUDIT.- UID(audtaudt) R(A) E(A) DATA(DEFAULT Auditor)
SRRAUDIT.- UID(pcspaudt) R(A) E(A) DATA(DEFAULT Production control and Scheduling)
SRRAUDIT.- UID(secaaudt) R(A) E(A) DATA(DEFAULT Security)
SRRAUDIT.- UID(syspaudt) R(A) W(L) A(L) E(A) DATA(DEFAULT SYSPROG)
SRRAUDIT.- UID(tstcaudt) R(A) W(L) A(L) E(A) DATA(DEFAULT Trusted STCs)"
  impact 0.5
  ref 'DPMS Target zOS SRRAUDIT for ACF2'
  tag check_id: 'C-26019r868231_chk'
  tag severity: 'medium'
  tag gid: 'V-224342'
  tag rid: 'SV-224342r868233_rule'
  tag stig_id: 'ZSRRA000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26007r868232_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-21724']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
