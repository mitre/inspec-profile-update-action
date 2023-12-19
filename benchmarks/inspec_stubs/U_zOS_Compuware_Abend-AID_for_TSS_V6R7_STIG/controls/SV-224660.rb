control 'SV-224660' do
  title 'Compuware Abend-AID installation data sets will be properly protected.'
  desc 'Compuware Abend-AID installation data sets have the ability to use privileged functions and/or have access to sensitive data.  Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(AIDRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZAID0000)

Verify that the accesses to the Compuware Abend-AID installation data sets are properly restricted.  If the following guidance is true, this is not a finding.

___	The TSS data set rules for the data sets restricts READ access to all authorized users.

___	The TSS data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

___	The TSS data set rules for the data sets specify that all (i.e., failures and successes) WRITE and/or greater access is logged.'
  desc 'fix', 'The IAO will ensure that WRITE and/or greater access to Compuware Abend-AID installation data sets is limited to System Programmers only, and all WRITE and/or greater access is logged.  READ access can be given to all authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged.  He will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be:
SYS2.ABENDAID.
SYS2A.ABENDAID.
SYS3A.ABENDAID.

The following commands are provided as a sample for implementing data set controls:

TSS ADD(SYS2) DSN(SYS2)
TSS ADD(SYS2A) DSN(SYS2A)
TSS ADD(SYS3A) DSN(SYS3A)
TSS PERMIT(syspaudt) DSN(SYS2.ABENDAID.V) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(syspaudt) DSN(SYS2.ABENDAID.V) ACCESS(READ)
TSS PERMIT(authorized users/ALL) DSN(SYS2.ABENDAID.V) ACCESS(READ)
TSS PERMIT(syspaudt) DSN(SYS2A.ABENDAID.V) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(syspaudt) DSN(SYS2A.ABENDAID.V) ACCESS(READ)
TSS PERMIT(authorized users/ALL) DSN(SYS2A.ABENDAID.V) ACCESS(READ)
TSS PERMIT(syspaudt) DSN(SYS3A.ABENDAID.V) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(syspaudt) DSN(SYS3A.ABENDAID.V) ACCESS(READ)
TSS PERMIT(authorized users/ALL) DSN(SYS3A.ABENDAID.V) ACCESS(READ)'
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for TSS'
  tag check_id: 'C-26343r519836_chk'
  tag severity: 'medium'
  tag gid: 'V-224660'
  tag rid: 'SV-224660r855151_rule'
  tag stig_id: 'ZAIDT000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26331r519837_fix'
  tag 'documentable'
  tag legacy: ['SV-43167', 'V-16932']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
