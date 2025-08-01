control 'SV-224279' do
  title 'CA VTAPE installation data sets are not properly protected.'
  desc 'CA VTAPE installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(VTARPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZVTA0000)

Verify that the accesses to the CA VTAPE installation data sets are properly restricted.
 
___	The ACF2 data set rules for the data sets restricts READ access to all authorized users.

___	The ACF2 data set rules for the data sets restricts UPDATE and/or ALTER access to systems programming personnel.

___	The ACF2 data set rules for the data sets specify that all (i.e., failures and successes) UPDATE and/or ALTER access are logged.'
  desc 'fix', 'The IAO will ensure that update and allocate access to CA VTAPE installation data sets is limited to System Programmers only, and all update and allocate access is logged.  Read access can be given to all authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged.  He will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS2.VTAPE.
SYS3.VTAPE. (data sets that are not altered by product STCs, can be more specific)

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS2)
VTAPE.- UID(<syspaudt>) R(A) W(L) A(L) E(A)
VTAPE.- UID(<tstcaudt>) R(A) W(L) A(L) E(A)
VTAPE.- UID(<audtaudt>) R(A) E(A)
VTAPE.- UID(authorized users) R(A) E(A)
VTAPE.- UID(<audtaudt>) R(A) E(A)
VTAPE.- UID(VTAPE STCs) R(A) E(A)

$KEY(SYS3)
VTAPE.- UID(<syspaudt>) R(A) W(L) A(L) E(A)
VTAPE.- UID(<tstcaudt>) R(A) W(L) A(L) E(A)
VTAPE.- UID(<audtaudt>) R(A) E(A)
VTAPE.- UID(authorized users) R(A) E(A)
VTAPE.- UID(VTAPE STCs) R(A) E(A)'
  impact 0.5
  ref 'DPMS Target zOS CA VTAPE for ACF2'
  tag check_id: 'C-25952r519665_chk'
  tag severity: 'medium'
  tag gid: 'V-224279'
  tag rid: 'SV-224279r855130_rule'
  tag stig_id: 'ZVTAA000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25940r519666_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-33824']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
