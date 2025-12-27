control 'SV-225581' do
  title 'NetView install data sets are not properly protected.'
  desc 'NetView install data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(NETVRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZNET0000)

b)	Verify that access to the NetView install data sets are properly restricted.
 
___	The TSS data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___	The TSS data set rules for the datasets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)	If all of the above are untrue, there is NO FINDING.

d)	If any of the above is true, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that update and allocate access to NetView install data sets is limited to System Programmers only,  and all update and allocate access is logged. All other users can have read access.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

Data sets to be protected will be: 
SYS2.NETVIEW 
SYS2A.NETVIEW
SYS3.NETVIEW

The following commands are provided as a sample for implementing dataset controls:

TSS PERMIT(syspaudt) DSN(SYS2.netview.) ACCESS(r)
TSS PERMIT(syspaudt) DSN(SYS2.netview.) ACCESS(all) ACTION(AUDIT)

TSS PERMIT(syspaudt) DSN(SYS2a.netview.) ACCESS(r)
TSS PERMIT(syspaudt) DSN(SYS2a.netview.) ACCESS(all) ACTION(AUDIT)

TSS PERMIT(syspaudt) DSN(SYS3.netview.) ACCESS(r)
TSS PERMIT(syspaudt) DSN(SYS3.netview.) ACCESS(all) ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target zOS NetView for TSS'
  tag check_id: 'C-27280r472539_chk'
  tag severity: 'medium'
  tag gid: 'V-225581'
  tag rid: 'SV-225581r855187_rule'
  tag stig_id: 'ZNETT000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27268r472540_fix'
  tag 'documentable'
  tag legacy: ['SV-27315', 'V-16932']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
