control 'SV-224666' do
  title 'IBM Communications Server Simple Mail Transfer Protocol (CSSMTP) STC data sets must be properly protected.'
  desc 'IBM Communications Server Simple Mail Transfer Protocol (CSSMTP) STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Examine the running started task for CSSMTP.

Verify that access to the IBM Communications Server Simple Mail Transfer Protocol (CSSMTP) STC data sets are properly restricted. The data sets to be protected are identified in the data set referenced in the DD statements of the CSSMTP started task(s) and/or batch job(s). 
Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(SMTPSTC)

Automated Analysis:
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZSMT0001)

If the following guidance is true, this is not a finding.

___ The TSS data set access authorizations restrict READ access to auditors.

___ The TSS data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The TSS data set access authorizations restrict WRITE and/or greater access to the product STC(s) and/or batch job(s).'
  desc 'fix', "Ensure that WRITE and/or greater access to the IBM Communications Server Simple Mail Transfer Protocol (CSSMTP) STC data sets are limited to systems programmers and CSSMTP STC and/or batch jobs only. READ access can be given to auditors at the ISSOs discretion.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have what type of access and if required which type of access is logged. The installing systems programmer will identify any additional groups requiring access to specific data sets, and once documented the installing systems programmer will work with the ISSO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific. 


The following commands are provided as an example for implementing data set controls: 

TSS PERMIT(audtaudt) DSN(SYS3.TCPIP.CSSMTP.) ACCESS(R)
TSS PERMIT(syspaudt) DSN(SYS3.TCPIP.CSSMTP.) ACCESS(R)
TSS PERMIT(tstcaudt) DSN(SYS3.TCPIP.CSSMTP.) ACCESS(R)
TSS PERMIT(icststc) DSN(SYS3.TCPIP.CSSMTP.) ACCESS(R)
TSS PERMIT(syspaudt) DSN(SYS3.TCPIP.CSSMTP.) ACCESS(ALL)
TSS PERMIT(tstcaudt) DSN(SYS3.TCPIP.CSSMTP.) ACCESS(ALL)
TSS PERMIT(icststc) DSN(SYS3.TCPIP.CSSMTP.) ACCESS(ALL)"
  impact 0.5
  ref 'DPMS Target zOS CSSMTP for TSS'
  tag check_id: 'C-26355r868754_chk'
  tag severity: 'medium'
  tag gid: 'V-224666'
  tag rid: 'SV-224666r868756_rule'
  tag stig_id: 'ZSMTT001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26343r868755_fix'
  tag 'documentable'
  tag legacy: ['SV-89727', 'V-17067']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
