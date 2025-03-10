control 'SV-224290' do
  title 'Compuware Abend-AID installation data sets will be properly protected.'
  desc 'Compuware Abend-AID installation data sets have the ability to use privileged functions and/or have access to sensitive data.  Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(AIDRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZAID0000)

Verify that the accesses to the Compuware Abend-AID installation data sets are properly restricted.  If the following guidance is true, this is not a finding.

___	The ACF2 data set rules for the data sets restricts READ access to all authorized users.

___	The ACF2 data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

___	The ACF2 data set rules for the data sets specify that all (i.e., failures and successes) WRITE and/or greater access is logged.'
  desc 'fix', "The IAO will ensure that WRITE and/or greater access to Compuware Abend-AID installation data sets is limited to System Programmers only, and all WRITE and/or greater access is logged.  READ access can be given to all authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged.  He will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be:
SYS2.ABENDAID.
SYS2A.ABENDAID.
SYS3A.ABENDAID.

The following commands are provided as a sample for implementing data set controls:

$KEY(S2A)
$PREFIX(SYS2)
ABENDAID.V-.- UID(syspaudt) R(A) W(L) A(L) E(A)
ABENDAID.V-.- UID(authorized users/*) R(A) E(A)

SET RULE
COMPILE 'ACF2.MVA.DSNRULES(S2A)' STORE

$KEY(SYS2A0A)
$MODE(ABORT)
$PREFIX(SYS2A)
ABENDAID.V-.- UID(syspaudt) R(A) W(L) A(L) E(A)
ABENDAID.V-.- UID(authorized users/*) R(A) E(A)

SET RULE
COMPILE 'ACF2.MVA.DSNRULES(SYS2A0A)' STORE

$KEY(SYS3A0A)
$PREFIX(SYS3A)
ABENDAID.V-.- UID(syspaudt) R(A) W(L) A(L) E(A)
ABENDAID.V-.- UID(authorized users/*) R(A) E(A)

SET RULE
COMPILE 'ACF2.MVA.DSNRULES(SYS3A0A)' STORE"
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for ACF2'
  tag check_id: 'C-25963r519797_chk'
  tag severity: 'medium'
  tag gid: 'V-224290'
  tag rid: 'SV-224290r855144_rule'
  tag stig_id: 'ZAIDA000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25951r519798_fix'
  tag 'documentable'
  tag legacy: ['SV-43165', 'V-16932']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
