control 'SV-224328' do
  title 'NetView install data sets are not properly protected.'
  desc 'NetView Install data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)	Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(NETVRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZNET0000)

b)	Verify that access to the NetView install data sets are properly restricted.
 
___	The ACF2 data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___	The ACF2 data set rules for the datasets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)	If all of the above are untrue, there is NO FINDING.

d)	If any of the above is true, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that update and allocate access to NetView install data sets is limited to System Programmers only,  and all update and allocate access is logged. Auditors should have read access.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

Data sets to be protected will be: 
SYS2.NETVIEW 
SYS2A.NETVIEW
SYS3.NETVIEW

The following commands are provided as a sample for implementing dataset controls: 

$KEY(SYS2)
NETVIEW.- UID(syspaudt) R(A) W(L) A(L) E(A)
NETVIEW.- UID(audtaudt) R(A) E(A)

$KEY(SYS2A)
NETVIEW.- UID(syspaudt) R(A) W(L) A(L) E(A)
NETVIEW.- UID(audtaudt) R(A) E(A)

$KEY(SYS3)
NETVIEW.- UID(syspaudt) R(A) W(L) A(L) E(A)
NETVIEW.- UID(audtaudt) R(A) E(A)'
  impact 0.5
  ref 'DPMS Target zOS NetView for ACF2'
  tag check_id: 'C-26005r520757_chk'
  tag severity: 'medium'
  tag gid: 'V-224328'
  tag rid: 'SV-224328r855183_rule'
  tag stig_id: 'ZNETA000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25993r520758_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-27308']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
