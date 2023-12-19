control 'SV-224726' do
  title 'IBM Hardware Configuration Definition (HCD) install data sets are not properly protected.'
  desc 'IBM Hardware Configuration Definition (HCD) product has the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(HCDRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZHCD0000)

Verify that access to the IBM Hardware Configuration Definition (HCD) install data sets are properly restricted.
 
___	The TSS data set rules for the data sets restricts READ access to auditors, automated operations, operators, and systems programming personnel.

___	The TSS data set rules for the data sets restricts UPDATE and/or ALL access to systems programming personnel.

___	The TSS data set rules for the data sets specifies that all (i.e., failures and successes) UPDATE and/or ALL access are logged.'
  desc 'fix', 'The IAO will ensure that update and ALL access to IBM Hardware Configuration Definition (HCD) install data sets is limited to System Programmers only, and all update and ALL access is logged. Auditors, automated operations, and operators should have READ access.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and ALL access and if required that all update and ALL access is logged. He will identify if any additional groups have update and/or ALL access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS1.SCBD*

The following commands are provided as a sample for implementing dataset controls: 

TSS PERMIT(audtaudt) DSN(SYS1.SCBD) ACCESS(R)
TSS PERMIT(autoaudt) DSN(SYS1.SCBD) ACCESS(R)
TSS PERMIT(operaudt) DSN(SYS1.SCBD) ACCESS(R)
TSS PERMIT(syspaudt) DSN(SYS1.SCBD) ACCESS(R)
TSS PERMIT(tstcaudt) DSN(SYS1.SCBD) ACCESS(R)
TSS PERMIT(syspaudt) DSN(SYS1.SCBD) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(tstcpaudt) DSN(SYS1.SCBD) ACCESS(ALL) ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target zOS HCD for TSS'
  tag check_id: 'C-26417r520217_chk'
  tag severity: 'medium'
  tag gid: 'V-224726'
  tag rid: 'SV-224726r855157_rule'
  tag stig_id: 'ZHCDT000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26405r520218_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-30546']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
