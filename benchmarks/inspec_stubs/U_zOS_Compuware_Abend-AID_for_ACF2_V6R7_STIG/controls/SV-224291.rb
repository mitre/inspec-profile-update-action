control 'SV-224291' do
  title 'Compuware Abend-AID STC data sets must be properly protected.'
  desc 'Compuware Abend-AID STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(AIDSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZAID0001)

Verify that the accesses to the Compuware Abend-AID STC data sets are properly restricted. If the following guidance is true, this is not a finding.

___ The ACF2 data set rules for the data sets restricts READ access to auditors.

___ The ACF2 data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set rules for the data sets restricts WRITE and/or greater access to the Compuware Abend-AID's STC(s) and/or batch user(s)."
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to Compuware Abend-AID STC data sets is limited to systems programmers and/or Compuware Abend-AID's STC(s) and/or batch user(s) only. READ access can be given to auditors.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged. The installing systems programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be:
SYS3.ABENDAID.

The following commands are provided as a sample for implementing data set controls:

$KEY(SYS3)
ABENDAID.- UID(<syspaudt>) R(A) W(A) A(A) E(A)
ABENDAID.- UID(<tstcaudt>) R(A) W(A) A(A) E(A)
ABENDAID.- UID(ABENDAID STCs) R(A) W(A) A(A) E(A)
ABENDAID.- UID(<audtaudt>) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for ACF2'
  tag check_id: 'C-25964r868069_chk'
  tag severity: 'medium'
  tag gid: 'V-224291'
  tag rid: 'SV-224291r868071_rule'
  tag stig_id: 'ZAIDA001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25952r868070_fix'
  tag 'documentable'
  tag legacy: ['SV-43168', 'V-17067']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
