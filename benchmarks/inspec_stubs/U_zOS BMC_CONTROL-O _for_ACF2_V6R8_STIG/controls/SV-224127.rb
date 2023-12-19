control 'SV-224127' do
  title 'BMC CONTROL-O STC data sets must be properly protected.'
  desc 'BMC CONTROL-O STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTOSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTO0001)

Verify that the accesses to the BMC CONTROL-O STC data sets are properly restricted. If the following guidance is true, this is not a finding.

___ The ACF2 data set access authorizations restrict READ access to auditors, operators, and domain level production control and scheduling personnel.

___ The ACF2 data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set access authorizations restrict UPDATE access to the BMC users and BMC STCs and/or batch users.'
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to BMC CONTROL-O STC data sets are limited to systems programmers only. UPDATE access can be given to BMC users and the BMC STCs and/or batch users. READ access can be given to auditors, operators, and domain level production control and scheduling personnel.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have what type of access and if required which type of access is logged. The installing systems programmer will identify any additional groups requiring access to specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS3.IOA.*.CTOO.

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS3)
IOA.-.CTOO.- UID(<syspaudt>) R(A) W(A) A(A) E(A)
IOA.-.CTOO.- UID(CONTROLO) R(A) W(A) E(A)
IOA.-.CTOO.- UID(<bmcuser>) R(A) W(A) E(A)
IOA.-.CTOO.- UID(<audtaudt>) R(A) E(A)
IOA.-.CTOO.- UID(<operaudt>) R(A) E(A)
IOA.-.CTOO.- UID(<pcspaudt>) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-O for ACF2'
  tag check_id: 'C-25800r868148_chk'
  tag severity: 'medium'
  tag gid: 'V-224127'
  tag rid: 'SV-224127r868150_rule'
  tag stig_id: 'ZCTOA001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25788r868149_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-31943']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
