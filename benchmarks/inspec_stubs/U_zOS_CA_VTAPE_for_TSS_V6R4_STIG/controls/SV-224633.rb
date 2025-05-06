control 'SV-224633' do
  title 'CA VTAPE STC data sets will be properly protected.'
  desc 'CA VTAPE STC data sets have the ability to use privileged functions and/or have access to sensitive data.  Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(VTASTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZVTA0001)

Verify that the accesses to the CA VTAPE STC data sets are properly restricted.  If the following guidance is true, this is not a finding.
 
___	The TSS data set rules for the data sets restricts READ access to auditors and authorized users.

___	The TSS data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel and Tape Management personnel.

___	The TSS data set rules for the data sets restricts WRITE and/or greater access to the CA VTAPE’s STC(s) and/or batch user(s).'
  desc 'fix', 'The IAO will ensure that WRITE and/or greater access to CA VTAPE STC data sets is limited to System Programmers, Tape Management personnel and/or CA VTAPE’s STC(s) and/or batch user(s) only.  Read access can be given to auditors and authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS3.VTAPE (data sets that are altered by the product’s STCs, this can be more specific)

The following commands are provided as a sample for implementing data set controls:

TSS PERMIT(<syspaudt>) DSN(SYS3.VTAPE) ACCESS(ALL)
TSS PERMIT(<tapeaudt>) DSN(SYS3.VTAPE) ACCESS(ALL)
TSS PERMIT(<tstcaudt>) DSN(SYS3.VTAPE) ACCESS(ALL)
TSS PERMIT(VTAPE STCs) DSN(SYS3.VTAPE) ACCESS(ALL)
TSS PERMIT(<audtaudt>) DSN(SYS3.VTAPE) ACCESS(R)
TSS PERMIT(authorize user) DSN(SYS3.VTAPE) ACCESS(R)'
  impact 0.5
  ref 'DPMS Target zOS CA VTAPE for TSS'
  tag check_id: 'C-26316r519689_chk'
  tag severity: 'medium'
  tag gid: 'V-224633'
  tag rid: 'SV-224633r519691_rule'
  tag stig_id: 'ZVTAT001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26304r519690_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-33829']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
