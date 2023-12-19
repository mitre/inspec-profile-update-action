control 'SV-224258' do
  title 'CA 1 Tape Management installation data sets must be properly protected.'
  desc 'CA 1 Tape Management installation data sets have the ability to use privileged functions and/or have access to sensitive data.  Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-       SENSITVE.RPT(CA1PROD)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-       PDI(ZCA10000)

Verify that the accesses to the CA 1 Tape Management installation data sets are properly restricted. If the following guidance is true, this is not a finding.

___       The ACF2 data set rules for the data sets restricts READ access to all authorized users.

___       The ACF2 data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

___       The ACF2 data set rules for the data sets specify that all (i.e., failures and successes) WRITE and/or greater access is logged.'
  desc 'fix', "Ensure that WRITE and/or greater access to CA 1 Tape Management installation data sets is limited to System Programmers only, and all WRITE and/or greater access is logged. READ access can be given to all authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged. He will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

The following is an example of the type of data sets to be protected:
SYS2.CA1.
SYS2A.CA1.*.CAILIB
SYS2A.CA1.*.CAILPA
Or
SYS2A.CA1.*.CTAPLINK
SYS3.CA1.
SYS3A.CA1.*.CAILIB
Or
SYS3A.CA1.*.CTAPLINK
SYS3A.CA1.*.CTAPLPA

The following commands are provided as a sample for implementing data set controls:

$KEY(S2C)
$PREFIX(SYS2)
CA1.V-.- UID(syspaudt) R(A) W(L) A(L) E(A)
CA1.V-.- UID(authorized users/*) R(A) E(A)

SET RULE
COMPILE 'ACF2.MVA.DSNRULES(S2C)' STORE

$KEY(SYS2A0C)
$MODE(ABORT)
$PREFIX(SYS2A)
CA1.V-.CAILIB UID(syspaudt) R(A) W(L) A(L) E(A)
CA1.V-.CAILIB UID(authorized users/*) R(A) E(A)
CA1.V-.CAILPA UID(syspaudt) R(A) W(L) A(L) E(A)
CA1.V-.CAILPA UID(authorized users/*) R(A) E(A)
Or
CA1.V-. CTAPLINK UID(syspaudt) R(A) W(L) A(L) E(A)
CA1.V-. CTAPLINK UID(authorized users/*) R(A) E(A)

SET RULE
COMPILE 'ACF2.MVA.DSNRULES(SYS2A0C)' STORE

$KEY(S3C)
$PREFIX(SYS3)
CA1.V-.- UID(syspaudt) R(A) W(L) A(L) E(A)
CA1.V-.- UID(authorized users/*) R(A) E(A)

SET RULE
COMPILE 'ACF2.MVA.DSNRULES(S3C)' STORE

$KEY(SYS3A0C)
$MODE(ABORT)
$PREFIX(SYS3A)
CA1.V-.CAILIB UID(syspaudt) R(A) W(L) A(L) E(A)
CA1.V-.CAILIB UID(authorized users/*) R(A) E(A)
Or
CA1.V-. CTAPLINK UID(syspaudt) R(A) W(L) A(L) E(A)
CA1.V-. CTAPLINK UID(authorized users/*) R(A) E(A)
CA1.V-. CTAPLPA UID(syspaudt) R(A) W(L) A(L) E(A)
CA1.V-. CTAPLPA UID(authorized users/*) R(A) E(A)

SET RULE
COMPILE 'ACF2.MVA.DSNRULES(SYS3A0C)' STORE"
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for ACF2'
  tag check_id: 'C-25931r519458_chk'
  tag severity: 'medium'
  tag gid: 'V-224258'
  tag rid: 'SV-224258r855102_rule'
  tag stig_id: 'ZCA1A000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25919r519459_fix'
  tag 'documentable'
  tag legacy: ['SV-39947', 'V-16932']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
