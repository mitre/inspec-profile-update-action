control 'SV-224632' do
  title 'CA VTAPE installation data sets are not properly protected.'
  desc 'CA VTAPE installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(VTARPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZVTA0000)

Verify that the accesses to the CA VTAPE installation data sets are properly restricted.
 
___	The TSS data set rules for the data sets restricts READ access to all authorized users.

___	The TSS data set rules for the data sets restricts UPDATE and/or ALL access to systems programming personnel.

___	The TSS data set rules for the data sets specify that all (i.e., failures and successes) UPDATE and/or ALL access are logged.'
  desc 'fix', 'The IAO will ensure that update and allocate access to CA VTAPE installation data sets is limited to System Programmers only, and all update and allocate access is logged.  Read access can be given to all authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS2.VTAPE.
SYS3.VTAPE. (data sets that are not altered by product STCs, can be more specific)

The following commands are provided as a sample for implementing data set controls:

TSS PERMIT(<syspaudt>) DSN(SYS2.VTAPE.) ACCESS(R)
TSS PERMIT(<syspaudt>) DSN(SYS2.VTAPE.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(<tstcaudt>) DSN(SYS2.VTAPE.) ACCESS(R)
TSS PERMIT(<tstcaudt>) DSN(SYS2.VTAPE.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(<audtaudt>) DSN(SYS2.VTAPE.) ACCESS(R)
TSS PERMIT(authorized users) DSN(SYS2.VTAPE.) ACCESS(R)
TSS PERMIT(VTAPE STCs) DSN(SYS2.VTAPE.) ACCESS(R)
TSS PERMIT(<syspaudt>) DSN(SYS3.VTAPE.) ACCESS(R)
TSS PERMIT(<syspaudt>) DSN(SYS3.VTAPE.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(<tstcaudt>) DSN(SYS3.VTAPE.) ACCESS(R)
TSS PERMIT(<tstcaudt>) DSN(SYS3.VTAPE.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(<audtaudt>) DSN(SYS3.VTAPE.) ACCESS(R)
TSS PERMIT(authorized users) DSN(SYS3.VTAPE.) ACCESS(R)
TSS PERMIT(VTAPE STCs) DSN(SYS3.VTAPE.) ACCESS(R)'
  impact 0.5
  ref 'DPMS Target zOS CA VTAPE for TSS'
  tag check_id: 'C-26315r519686_chk'
  tag severity: 'medium'
  tag gid: 'V-224632'
  tag rid: 'SV-224632r855132_rule'
  tag stig_id: 'ZVTAT000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26303r519687_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-33826']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
