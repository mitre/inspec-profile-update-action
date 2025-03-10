control 'SV-224333' do
  title 'Quest NC-Pass STC data sets will be properly protected.'
  desc 'Quest NC-Pass STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(NCPASSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZNCP0001)

Verify that the accesses to the Quest NC-Pass STC data sets are properly restricted.

___ The ACF2 data set rules for the data sets restricts READ access to auditors.

___ The ACF2 data set rules for the data sets restricts WRITE access to domain level security administrators.

___ The ACF2 data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set rules for the data sets restricts WRITE and/or greater access to the Quest NC-Pass's STC(s) and/or batch user(s)."
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to Quest NC-Pass STC data sets is limited to systems programmers and/or Quest NC-Pass's STC(s) and/or batch user(s) only. UPDATE access can be given to domain level security administrators. READ access can be given to auditors.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be:
SYS3.NCPASS.*.PASSCAF
SYS3.NCPASS.*.PASSVSDD

The following commands are provided as a sample for implementing data set controls:

$KEY(SYS3)
NCPASS.-.PASSCAF.- UID(<syspaudt>) R(A) W(A) A(A) E(A)
NCPASS.-.PASSCAF.- UID(<tstcaudt>) R(A) W(A) A(A) E(A)
NCPASS.-.PASSCAF.- UID(NCPASS STCs) R(A) W(A) A(A) E(A)
NCPASS.-.PASSCAF.- UID(secaaudt) R(A) W(A) E(A)
NCPASS.-.PASSCAF.- UID(<audtaudt>) R(A) E(A)
NCPASS.-.PASSVSDD.- UID(<syspaudt>) R(A) W(A) A(A) E(A)
NCPASS.-.PASSVSDD.- UID(<tstcaudt>) R(A) W(A) A(A) E(A)
NCPASS.-.PASSVSDD.- UID(NCPASS STCs) R(A) W(A) E(A)
NCPASS.-.PASSVSDD.- UID(<secaaudt>) R(A) W(A) E(A)
NCPASS.-.PASSVSDD.- UID(<audtaudt>) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS Quest NC-Pass for ACF2'
  tag check_id: 'C-26010r868213_chk'
  tag severity: 'medium'
  tag gid: 'V-224333'
  tag rid: 'SV-224333r868215_rule'
  tag stig_id: 'ZNCPA001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25998r868214_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-40866']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
