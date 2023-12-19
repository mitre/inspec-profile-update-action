control 'SV-224266' do
  title 'CA Auditor User data sets are not properly protected.'
  desc 'CA Auditor User data sets have the ability to use privileged functions and/or have access to sensitive data.  Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(ADTUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZADT0002)

Verify that the accesses to the CA Auditor User data sets are properly restricted.

___	The ACF2 data set rules for the data sets restricts UPDATE and/or ALTER access to systems programming personnel, security personnel and auditors.'
  desc 'fix', 'The IAO will ensure that update and allocate access to CA Auditor User data sets are limited to System Programmers, security personnel and auditors.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged.  He will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS3.EXAMINE

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS3)
EXAMINE.- UID(<syspaudt>) R(A) W(A) A(A) E(A)
EXAMINE.- UID(<audtaudt>) R(A) W(A) A(A) E(A)
EXAMINE.- UID(<secaaudt>) R(A) W(A) A(A) E(A)'
  impact 0.5
  ref 'DPMS Target zOS CA Auditor for ACF2'
  tag check_id: 'C-25939r519548_chk'
  tag severity: 'medium'
  tag gid: 'V-224266'
  tag rid: 'SV-224266r519550_rule'
  tag stig_id: 'ZADTA002'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25927r519549_fix'
  tag 'documentable'
  tag legacy: ['V-21592', 'SV-32205']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
