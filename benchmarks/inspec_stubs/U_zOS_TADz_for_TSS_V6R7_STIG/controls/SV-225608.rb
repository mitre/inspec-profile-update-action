control 'SV-225608' do
  title 'Tivoli Asset Discovery for z/OS (TADz) Install data sets are not properly protected.'
  desc 'Tivoli Asset Discovery for z/OS (TADz) Install data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(TADZRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZTAD0000)

b)	Verify that access to the TADz Install data sets are properly restricted.
 
___	The TSS data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___	The TSS data set rules for the data sets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)	If all of the above are untrue, there is NO FINDING.

d)	If any of the above is true, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that update and allocate/create access to program product data sets is limited to System Programmers only, and all update and allocate/create access is logged.  Auditors should have read access.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and allocate/create access and if required that all update and allocate/create access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

Data sets to be protected will be: 
SYS2.TADZ 
SYS2.TADZ .V-.SHSIMOD1 (optional fully-qualified APF).
SYS3.TADZ 

The following commands are provided as a sample for implementing dataset controls: 

TSS PERMIT(syspaudt) DSN(SYS2.TADZ.) ACCESS(R) 
TSS PERMIT(syspaudt) DSN(SYS2.TADZ.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(audtaudt) DSN(SYS2.TADZ.) ACCESS(R) 

TSS PERMIT(syspaudt) DSN(sys2.tadz.*.shsimod1) ACCESS(R) 
TSS PERMIT(syspaudt) DSN(sys2.tadz.*.shsimod1) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(audtaudt) DSN(SYS2.TADZ.*.shsimod1) ACCESS(R) 

TSS PERMIT(syspaudt) DSN(SYS3.TADZ.) ACCESS(R)
TSS PERMIT(syspaudt) DSN(SYS3.TADZ.) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(audtaudt) DSN(SYS3.TADZ.) ACCESS(R)'
  impact 0.5
  ref 'DPMS Target zOS TADz for TSS'
  tag check_id: 'C-27308r472623_chk'
  tag severity: 'medium'
  tag gid: 'V-225608'
  tag rid: 'SV-225608r855215_rule'
  tag stig_id: 'ZTADT000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-27296r472624_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-28471']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
