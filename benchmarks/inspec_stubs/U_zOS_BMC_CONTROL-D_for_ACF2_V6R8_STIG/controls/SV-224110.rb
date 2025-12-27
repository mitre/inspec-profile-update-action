control 'SV-224110' do
  title 'BMC CONTROL-D user data sets must be properly protected.'
  desc 'BMC CONTROL-D User data sets, CDAM and Repository, have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTMUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTD0002)

Verify that the accesses to the BMC CONTROL-D User data sets are properly restricted. If the following guidance is true, this is not a finding.


___ The ACF2 data set access authorizations restrict READ access to auditors.

___ The ACF2 data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set access authorizations restrict WRITE and/or greater access to the BMC STCs and/or batch users.

___ The ACF2 data set access authorizations restrict UPDATE access to centralized and decentralized security personnel, and/or CONTROL-D end users.'
  desc 'fix', "The ISSO must ensure that WRITE and/or greater access to BMC CONTROL-D User data sets are limited to systems programmers and BMC STCs and/or batch users. Additionally, UPDATE access can be given to centralized and decentralized security personnel, and BMC users. The ISSO can approve ALLOC access in circumstances where it is determined to be necessary and appropriate for systems operations to execute in a normal secure manner. READ access can be given to auditors.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer must identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS3.IOA.*.CTDR.
CTRUSR.
CTDSRV.
CTDJB1.

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS3)
IOA.-.CTDR.- UID(syspaudt) R(A) W(A) A(A) E(A)
IOA.-.CTDR.- UID(tstcaudt) R(A) W(A) A(A) E(A)
IOA.-.CTDR.- UID(BMC STCs) R(A) W(A) A(A) E(A)
IOA.-.CTDR.- UID(bmcuser) R(A) W(A) E(A)
IOA.-.CTDR.- UID(secaaudt) R(A) W(A) E(A)
IOA.-.CTDR.- UID(secdaudt) R(A) W(A) E(A)
IOA.-.CTDR.- UID(audtaudt) R(A) E(A)

$KEY(CTRUSR)
- UID(syspaudt) R(A) W(A) A(A) E(A)
- UID(tstcaudt) R(A) W(A) A(A) E(A)
- UID(BMC STCs) R(A) W(A) A(A) E(A)
- UID(bmcuser) R(A) W(A) E(A)
- UID(secaaudt) R(A) W(A) E(A)
- UID(secdaudt) R(A) W(A) E(A)
- UID(audtaudt) R(A) E(A)

$KEY(CTDSRV)
- UID(syspaudt) R(A) W(A) A(A) E(A)
- UID(tstcaudt) R(A) W(A) A(A) E(A)
- UID(BMC STCs) R(A) W(A) A(A) E(A)
- UID(bmcuser) R(A) W(A) E(A)
- UID(secaaudt) R(A) W(A) E(A)
- UID(secdaudt) R(A) W(A) E(A)
- UID(audtaudt) R(A) E(A)

$KEY(CTDJB1)
- UID(syspaudt) R(A) W(A) A(A) E(A)
- UID(tstcaudt) R(A) W(A) A(A) E(A)
- UID(BMC STCs) R(A) W(A) A(A) E(A)
- UID(bmcuser) R(A) W(A) E(A)
- UID(secaaudt) R(A) W(A) E(A)
- UID(secdaudt) R(A) W(A) E(A)
- UID(audtaudt) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-D for ACF2'
  tag check_id: 'C-25783r518656_chk'
  tag severity: 'medium'
  tag gid: 'V-224110'
  tag rid: 'SV-224110r868126_rule'
  tag stig_id: 'ZCTDA002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25771r868125_fix'
  tag 'documentable'
  tag legacy: ['SV-32162', 'V-21592']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
