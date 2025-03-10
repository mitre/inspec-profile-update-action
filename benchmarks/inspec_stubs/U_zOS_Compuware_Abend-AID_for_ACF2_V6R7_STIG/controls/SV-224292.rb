control 'SV-224292' do
  title 'Compuware Abend-AID user data sets must be properly protected.'
  desc 'Compuware Abend-AID user data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(AIDUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZAID0002)

Verify that the accesses to the following Compuware Abend-AID user data sets are properly restricted:
Region dump datasets
Report databases
Source listing files/source listing shared directories

If the following guidance is true, this is not a finding.

___ The ACF2 data set rules for the listed data sets restricts READ access to auditors.

___ The ACF2 data set rules for the listed data sets restricts WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set rules for the listed data sets restricts WRITE and/or greater access to the Compuware Abend-AID's STC(s) and/or batch user(s).

___ The ACF2 data set rules for the listed data sets restricts WRITE access to Application Development Programmers and Application Production Support Team members."
  desc 'fix', "Ensure that WRITE and/or greater access to Compuware Abend-AID user data sets is limited to systems programmers and Compuware Abend-AID STC(s) and/or batch user(s) only. Ensure that WRITE access to Compuware Abend-AID user data sets is limited to Application Development Programmers and Application Production Support Team members. Read access can be given to auditors.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be:

Region dump datasets
Report databases
Source listing files/source listing shared directories

The following commands are provided as a sample for implementing data set controls:

$KEY(S3A) 
$PREFIX(SYS3)
ABENDAID.SHARED-.- UID(appdaudt) R(A) W(A)
ABENDAID.SHARED-.- UID(appsaudt) R(A) W(A)
ABENDAID.SHARED-.- UID(AbendAID STCs) R(A) W(A) A(A) E(A)
ABENDAID.SHARED-.- UID(syspaudt) R(A) W(A) A(A) E(A)

ABENDAID.SHARED-.- UID(tstcaudt) R(A) W(A) A(A) E(A)
ABENDAID.SHARED-.- UID(audtaudt) R(A)
ABENDAID.REPORTDB-.- UID(appdaudt) R(A) W(A)
ABENDAID.REPORTDB-.- UID(appsaudt) R(A) W(A)
ABENDAID.REPORTDB-.- UID(AbendAID STCs) R(A) W(A) A(A) E(A)
ABENDAID.REPORTED-.- UID(syspaudt) R(A) W(A) A(A) E(A)
ABENDAID.REPORTED-.- UID(tstcaudt) R(A) W(A) A(A) E(A) 
ABENDAID.REPORTDB-.- UID(audtaudt) R(A)

SET RULE
COMPILE 'ACF2.MVA.DSNRULES(S3A)' STORE"
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for ACF2'
  tag check_id: 'C-25965r868072_chk'
  tag severity: 'medium'
  tag gid: 'V-224292'
  tag rid: 'SV-224292r868074_rule'
  tag stig_id: 'ZAIDA002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25953r868073_fix'
  tag 'documentable'
  tag legacy: ['SV-75837', 'V-21592']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
