control 'SV-224607' do
  title 'BMC MAINVIEW for z/OS installation data sets are not properly protected.'
  desc 'BMC MAINVIEW for z/OS installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(MVZRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZMVZ0000)

Verify that the accesses to the BMC MAINVIEW for z/OS installation data sets are properly restricted.
 
___	The TSS data set rules for the data sets restricts READ access to all authorized users.

___	The TSS data set rules for the data sets restricts UPDATE and/or ALL access to systems programming personnel.

___	The TSS data set rules for the data sets specify that all (i.e., failures and successes) UPDATE and/or ALL access are logged.'
  desc 'fix', 'The IAO will ensure that update and allocate access to BMC MAINVIEW for z/OS installation data sets is limited to System Programmers only, and all update and allocate access is logged.  Read access can be given to all authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS2.BMCVIEW.
SYS3.BMCVIEW. (data sets that are not altered by product STCs, can be more specific)

The following commands are provided as a sample for implementing data set controls:

TSS PERMIT(<syspaudt>) DSN(SYS2.BMCVIEW.) ACCESS(R)
TSS PERMIT(<syspaudt>) DSN(SYS2.BMCVIEW.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(<tstcaudt>) DSN(SYS2.BMCVIEW.) ACCESS(R)
TSS PERMIT(<tstcaudt>) DSN(SYS2.BMCVIEW.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(<audtaudt>) DSN(SYS2.BMCVIEW.) ACCESS(R)
TSS PERMIT(authorized users) DSN(SYS2.BMCVIEW.) ACCESS(R)
TSS PERMIT(MAINVIEW STCs) DSN(SYS2.BMCVIEW.) ACCESS(R)
TSS PERMIT(<syspaudt>) DSN(SYS3.BMCVIEW.) ACCESS(R)
TSS PERMIT(<syspaudt>) DSN(SYS3.BMCVIEW.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(<tstcaudt>) DSN(SYS3.BMCVIEW.) ACCESS(R)
TSS PERMIT(<tstcaudt>) DSN(SYS3.BMCVIEW.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(<audtaudt>) DSN(SYS3.BMCVIEW.) ACCESS(R)
TSS PERMIT(authorized users) DSN(SYS3.BMCVIEW.) ACCESS(R)
TSS PERMIT(MAINVIEW STCs) DSN(SYS3.BMCVIEW.) ACCESS(R)'
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for TSS'
  tag check_id: 'C-26290r518998_chk'
  tag severity: 'medium'
  tag gid: 'V-224607'
  tag rid: 'SV-224607r855099_rule'
  tag stig_id: 'ZMVZT000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26278r518999_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-33837']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
