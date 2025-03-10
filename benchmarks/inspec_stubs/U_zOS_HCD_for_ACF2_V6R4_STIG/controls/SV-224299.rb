control 'SV-224299' do
  title 'IBM Hardware Configuration Definition (HCD) install data sets are not properly protected.'
  desc 'IBM Hardware Configuration Definition (HCD) product has the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(HCDRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZHCD0000)

Verify that access to the IBM Hardware Configuration Definition (HCD) install data sets are properly restricted.
 
___	The ACF2 data set rules for the data sets restricts READ access to auditors, automated operations, operators, and systems programming personnel.

___	The ACF2 data set rules for the data sets restricts UPDATE and/or ALTER access to systems programming personnel.

___	The ACF2 data set rules for the data sets specifies that all (i.e., failures and successes) UPDATE and/or ALTER access are logged.'
  desc 'fix', 'The IAO will ensure that update and allocate access to IBM Hardware Configuration Definition (HCD) install data sets is limited to System Programmers only, and all update and alter access is logged. Auditors, automated operations, and operators should have READ access.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS1.SCBD*

The following commands are provided as a sample for implementing dataset controls: 

$KEY(SYS1)
SCBD- UID(syspaudt) R(A) W(L) A(L) E(A)
SCBD- UID(tstcaudt) R(A) W(L) A(L) E(A)
SCBD- UID(audtaudt) R(A) E(A)
SCBD- UID(autoaudt) R(A) E(A)
SCBD- UID(operaudt) R(A) E(A)'
  impact 0.5
  ref 'DPMS Target zOS HCD for ACF2'
  tag check_id: 'C-25976r520199_chk'
  tag severity: 'medium'
  tag gid: 'V-224299'
  tag rid: 'SV-224299r855153_rule'
  tag stig_id: 'ZHCDA000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25964r520200_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-30544']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
