control 'SV-224332' do
  title 'Quest NC-Pass installation data sets will be properly protected.'
  desc 'Quest NC-Pass installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(NCPASRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZNCP0000)

Verify that the accesses to the Quest NC-Pass installation data sets are properly restricted.  If the following guidance is true, this is not a finding.
 
___	The ACF2 data set rules for the data sets restricts READ access to all authorized users.

___	The ACF2 data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

___	The ACF2 data set rules for the data sets specify that all (i.e., failures and successes) WRITE and/or greater access is logged.'
  desc 'fix', 'The IAO will ensure that WRITE and/or greater access to Quest NC-Pass installation data sets is limited to System Programmers only, and all WRITE and/or greater access is logged.  READ access can be given to all authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged.  He will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be:
SYS2.NCPASS.
SYS3.NCPASS. (data sets that are not altered by product STCs, can be more specific)

The following commands are provided as a sample for implementing data set controls:

$KEY(SYS2)
NCPASS.- UID(<syspaudt>) R(A) W(L) A(L) E(A)
NCPASS.- UID(<tstcaudt>) R(A) W(L) A(L) E(A)
NCPASS.- UID(<audtaudt>) R(A) E(A)
NCPASS.- UID(*) R(A) E(A)

$KEY(SYS3)
NCPASS.- UID(<syspaudt>) R(A) W(L) A(L) E(A)
NCPASS.- UID(<tstcaudt>) R(A) W(L) A(L) E(A)
NCPASS.- UID(<audtaudt>) R(A) E(A)
NCPASS.- UID(*) R(A) E(A)'
  impact 0.5
  ref 'DPMS Target zOS Quest NC-Pass for ACF2'
  tag check_id: 'C-26009r520787_chk'
  tag severity: 'medium'
  tag gid: 'V-224332'
  tag rid: 'SV-224332r855189_rule'
  tag stig_id: 'ZNCPA000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25997r520788_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-40863']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
