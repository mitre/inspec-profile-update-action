control 'SV-224265' do
  title 'CA Auditor installation data sets are not properly protected.'
  desc 'CA Auditor installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(ADTRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZADT0000)

Verify that the accesses to the CA Auditor installation data sets are properly restricted.
 
___ The ACF2 data set rules for the data sets restricts READ access to auditors, security administrators, and/or CA Auditor's STCs and batch users.

___ The ACF2 data set rules for the data sets restricts UPDATE and/or ALTER access to systems programming personnel.

___ The ACF2 data set rules for the data sets specify that all (i.e., failures and successes) UPDATE and/or ALTER access are logged."
  desc 'fix', "The ISSO will ensure that update and allocate access to CA Auditor installation data sets is limited to systems programmers only, and all update and allocate access is logged. Read access can be given to auditors, security administrators, and/or CA Auditor's STCs and batch users.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS2.EXAMINE
SYS2A.EXAMINE

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS2)
EXAMINE.- UID(<syspaudt>) R(A) W(L) A(L) E(A)
EXAMINE.- UID(<audtaudt>) R(A) E(A)
EXAMINE.- UID(<secaaudt>) R(A) E(A)
EXAMINE.- UID(EXAMMON) R(A) E(A)
$KEY(SYS2A)
EXAMINE.- UID(<syspaudt>) R(A) W(L) A(L) E(A)
EXAMINE.- UID(<audtaudt>) R(A) E(A)
EXAMINE.- UID(<secaaudt>) R(A) E(A)
EXAMINE.- UID(EXAMMON) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS CA Auditor for ACF2'
  tag check_id: 'C-25938r868063_chk'
  tag severity: 'medium'
  tag gid: 'V-224265'
  tag rid: 'SV-224265r868065_rule'
  tag stig_id: 'ZADTA000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25926r868064_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-31918']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
