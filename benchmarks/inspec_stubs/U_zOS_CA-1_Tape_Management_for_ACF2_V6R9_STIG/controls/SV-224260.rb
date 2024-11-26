control 'SV-224260' do
  title 'CA 1 Tape Management TMC, AUDIT and optional RDS and VPD data sets will be properly protected.'
  desc 'CA 1 Tape Management TMC and AUDIT and optional data sets control the operations and access to the tape management system, and site specific information regarding tape volumes.  Unauthorized access to these data sets could threaten the integrity and availability of the CA 1 Tape Management System, and compromise the confidentiality of customer data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(CA1RPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZCA10003)

Ensure that all CA 1 Tape Management TMC, AUDIT and optional RDS and VPD data sets are properly protected.  If the following guidance is true, this is not a finding.

___	The ACF2 data set access authorizations restricts READ access to application support personnel, production control and scheduling personnel, operations personnel, and auditors.

___	The ACF2 data set access authorizations restricts WRITE and/or greater access to only systems programming personnel and tape management personnel.

___	The ACF2 data set access authorizations restricts UPDATE access is limited to CA 1 batch production jobs, and CA 1 started tasks.

___	The ACF2 data set access authorizations specify that all (i.e., failures and successes) ALTER access are logged.'
  desc 'fix', 'The IAO will ensure that WRITE and/or greater access to CA 1 TMC, AUDIT and optional RDS and VPD data sets are limited to only systems programming personnel and tape management personnel.  UPDATE access can be given to CA 1 STCs and/or batch users.  READ access can be given to application support personnel, production control and scheduling personnel, operations personnel, and auditors.  ALTER access will be logged.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged.  He will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

(Note:  The data sets and/or data set prefixes identified below are examples of a possible installation.  The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product’s installation guide and can be site specific.)

Due to the unique file structure of the TMC and Audit data sets, CA 1 uses the YSVC programs to handle all direct I/O activity.  Because standard OPEN/CLOSE macros are not used, typical data set security checks are not performed.  Even if a user does not have read authority to these data sets, the YSVC programs can enable that user to read and update records within these files.  Therefore, control READ access to the TMC and Audit data sets by the YSVCUNCD and YSVCCOND resource names.  Typical users should be restricted to conditional READ access.

Restrict CA 1 batch production jobs, and CA 1 started tasks to the following access authority:  Unconditional READ and UPDATE access to the TMC, Audit, Retention, and Vault Pattern Description data sets.  NOTE: READ and UPDATE access to the TMC and Audit data sets are controlled by the YSVCUNCD and YSVCCOND resource names, and by standard ACP data set controls, because some CA 1 utilities use conventional OPEN/CLOSE methods.

The following commands are provided as a sample for implementing data set controls:

SET RULE
$KEY(S3C)
$PREFIX(SYS3)
CA1.AUDIT UID(<audtaudt>) R(A) E(A)
CA1.AUDIT UID(<operaudt>) R(A) E(A)
CA1.AUDIT UID(<pcspaudt>) R(A) E(A)
CA1.AUDIT UID(CA1 STCs) R(A) W(A) E(A)
CA1.AUDIT UID(<syspaudt>) R(A) W(A) A(L) E(A)
CA1.AUDIT UID(<tapeaudt>) R(A) W(A) A(L) E(A)
CA1.AUDIT UID(<tstcaudt>) R(A) W(A) A(L) E(A)
CA1.RDS UID(<syspaudt>) R(A) W(A) A(L) E(A)
CA1.RDS UID(<tapeaudt>) R(A) W(A) A(L) E(A)
CA1.RDS UID(<tstcaudt>) R(A) W(A) A(L) E(A)
CA1.TMC UID(<appsaudt>) R(A) E(A)
CA1.TMC UID(<audtaudt>) R(A) E(A)
CA1.TMC UID(<operaudt>) R(A) E(A)
CA1.TMC UID(<pcspaudt>) R(A) E(A)
CA1.TMC UID(CA1 STCs) R(A) W(A) E(A)
CA1.TMC UID(<syspaudt>) R(A) W(A) A(L) E(A)
CA1.TMC UID(<tapeaudt>) R(A) W(A) A(L) E(A)
CA1.TMC UID(<tstcaudt>) R(A) W(A) A(L) E(A)
CA1.VPD UID(<syspaudt>) R(A) W(A) A(L) E(A)
CA1.VPD UID(<tapeaudt>) R(A) W(A) A(L) E(A)
CA1.VPD UID(<tstcaudt>) R(A) W(A) A(L) E(A)'
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for ACF2'
  tag check_id: 'C-25933r519464_chk'
  tag severity: 'medium'
  tag gid: 'V-224260'
  tag rid: 'SV-224260r519466_rule'
  tag stig_id: 'ZCA1A003'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25921r519465_fix'
  tag 'documentable'
  tag legacy: ['V-17072', 'SV-40070']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
