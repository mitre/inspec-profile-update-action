control 'SV-224639' do
  title 'CA-1 Tape Management STC data sets must be properly protected.'
  desc 'CA-1 Tape Management STC data sets have the ability to use privileged functions and/or have access to sensitive data.  Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(CA1STC)


Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCA10001)

Verify that the accesses to CA1 Tape Management Started Tasks (STCs) data sets are properly restricted.  If the following guidance is true, this is not a finding.
 
___	The TSS data set access authorizations restrict READ access to auditors.

___	The TSS data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___	The TSS data set access authorizations restrict WRITE and/or greater access to CA1 Tape Management STCs and/or batch users.'
  desc 'fix', 'Ensure that WRITE and/or greater access to CA1 Tape management STC data sets is limited to System Programmers and/or CA1 Tape management STC(s) and/or batch user(s) only.  READ access can be given to auditors.
 (Note:  The data sets and/or data set prefixes identified below are examples of a possible installation.  The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product’s installation guide and can be site specific.)

Data sets to be protected will be: 
CA1.TMS*  (Data sets that are altered by the product’s STCs, this can be more specific.)

The following commands are provided as a sample for implementing data set controls: 

TSS PERMIT(<syspaudt>) DSN(SYS3.CA1.TMS*.**) ACCESS(ALL)
TSS PERMIT(<Tape Management STCs and/or batch users  >) DSN(SYS3.CA1.TMS*.**)  ACCESS(ALL)
TSS PERMIT(<audtaudt >) DSN(SYS3.CA1.TMS*.**)'
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for TSS'
  tag check_id: 'C-26322r519521_chk'
  tag severity: 'medium'
  tag gid: 'V-224639'
  tag rid: 'SV-224639r519523_rule'
  tag stig_id: 'ZCA1T001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26310r519522_fix'
  tag 'documentable'
  tag legacy: ['SV-87415', 'V-17067']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
