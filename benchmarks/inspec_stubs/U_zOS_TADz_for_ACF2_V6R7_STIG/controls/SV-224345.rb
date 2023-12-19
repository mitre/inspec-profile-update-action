control 'SV-224345' do
  title 'Tivoli Asset Discovery for zOS (TADz) STC and/or batch data sets are not properly protected.'
  desc 'Tivoli Asset Discovery for zOS (TADz) STC data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(TADZSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZTAD0001)

For all (TADz) STC and/or batch data sets:

If the UPDATE or greater access is restricted to systems programming personnel and the product STC(s) and/or batch job(s) this is not a finding.

If any job scheduling products are in use and access is restricted to READ this is not a finding.

If auditors have READ access this is not a finding.'
  desc 'fix', "Grant update and alter access to Tivoli Asset Discovery for z/OS (TADz) STC and/or batch data sets are limited to system programmers and TADz STC and/or batch jobs only. 

Grant read access to any scheduling products that are in use.
 
Grant read access to auditors at the ISSO's discretion.

Identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. Identify if any additional groups have update access for specific data sets, and assure that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS3.TADZ

The following commands are provided as a sample for implementing dataset controls: 

$KEY(SYS3)
TADZ.- UID(syspaudt) R(A) W(A) A(A) E(A)
TADZ.- UID(audtaudt) R(A) E(A)
TADZ.-.UM.- UID(batchid TADZINQ) R(A) W(A) A(A) E(A)
TADZ.-.IQ.- UID(batchid TADZINQ) R(A) W(A) A(A) E(A)
TADZ.-.UIQ.- UID(batchid TADZINQ) R(A) W(A) A(A) E(A)
TADZ.- UID(stc id TADZMON) R(A) W(A) A(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS TADz for ACF2'
  tag check_id: 'C-26022r868234_chk'
  tag severity: 'medium'
  tag gid: 'V-224345'
  tag rid: 'SV-224345r868236_rule'
  tag stig_id: 'ZTADA001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26010r868235_fix'
  tag 'documentable'
  tag legacy: ['SV-28547', 'V-17067']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
