control 'SV-224523' do
  title 'Quest NC-Pass installation data sets will be properly protected.'
  desc 'Quest NC-Pass installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(NCPASRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZNCP0000)

Verify that the accesses to the Quest NC-Pass installation data sets are properly restricted.  If the following guidance is true, this is not a finding.
 
___	The RACF data set rules for the data sets restricts READ access to all authorized users.

___	The RACF data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

___	The RACF data set rules for the data sets specify that all (i.e., failures and successes) WRITE and/or greater access is logged.

___	The RACF data set rules for the data sets specify UACC(NONE) and NOWARNING.'
  desc 'fix', "The IAO will ensure that WRITE and/or greater access to Quest NC-Pass installation data sets is limited to System Programmers only, and all WRITE and/or greater access is logged.  READ access can be given to all authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged.  He will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be:
SYS2.NCPASS.
SYS3.NCPASS. (data sets that are not altered by product STCs, can be more specific)

The following commands are provided as a sample for implementing data set controls:

ad 'SYS2.NCPASS.**' uacc(none) owner(sys2) -
	audit(success(update) failures(read)) -
	data('Quest NC-Pass Install DS')
pe 'SYS2.NCPASS.**' id(<syspaudt> <tstcaudt>) acc(a)
pe 'SYS2.NCPASS.**' id(<audtaudt>) acc(r)
pe 'SYS2.NCPASS.**' id(*) acc(r)

ad 'SYS3.NCPASS.**' uacc(none) owner(sys3) -
	audit(success(update) failures(read)) -
	data('Quest NC-Pass Install DS')
pe 'SYS3.NCPASS.**' id(<syspaudt> <tstcaudt>) acc(a)
pe 'SYS3.NCPASS.**' id(<audtaudt>) acc(r)
pe 'SYS3.NCPASS.**' id(*) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS Quest NC-Pass for RACF'
  tag check_id: 'C-26206r520799_chk'
  tag severity: 'medium'
  tag gid: 'V-224523'
  tag rid: 'SV-224523r855191_rule'
  tag stig_id: 'ZNCPR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26194r520800_fix'
  tag 'documentable'
  tag legacy: ['SV-40864', 'V-16932']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
