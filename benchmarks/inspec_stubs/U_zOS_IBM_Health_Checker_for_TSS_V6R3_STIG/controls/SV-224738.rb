control 'SV-224738' do
  title 'IBM Health Checker STC data sets will be properly protected.'
  desc 'IBM Health Checker STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(HCKSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZHCK0001)

Verify that the accesses to the IBM Health Checker STC data sets are properly restricted. If the following guidance is true, this is not a finding.

___ The TSS data set rules for the data sets restricts READ access to auditors.

___ The TSS data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

___ The TSS data set rules for the data sets restricts WRITE and/or greater access to the IBM Health Checker's STC(s) and/or batch user(s)."
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to IBM Health Checker STC data sets is limited to systems programmers and/or IBM Health Checker's STC(s) and/or batch user(s) only. READ access can be given to auditors.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged. The installing systems programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system. The dataset to be protected can be found in the HZSPROC STC member in HZSPDATA DD statement.

Data sets to be protected will be:
SYS3.*.HZSPDATA

The following commands are provided as a sample for implementing data set controls:

TSS ADD(SYS3) DSN(SYS3)
TSS PERMIT(syspaudt) DSN(SYS3.MMG.HZSPDATA) ACCESS(ALL)
TSS PERMIT(Health Checker STCs) DSN(SYS3.MMG.HZSPDATA) ACCESS(ALL)
TSS PERMIT(audtaudt) DSN(SYS3.MMG.HZSPDATA) ACCESS(READ)"
  impact 0.5
  ref 'DPMS Target zOS IBM Health Checker for TSS'
  tag check_id: 'C-26429r868697_chk'
  tag severity: 'medium'
  tag gid: 'V-224738'
  tag rid: 'SV-224738r868699_rule'
  tag stig_id: 'ZHCKT001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26417r868698_fix'
  tag 'documentable'
  tag legacy: ['SV-43173', 'V-17067']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
