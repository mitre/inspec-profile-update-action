control 'SV-224652' do
  title 'CL/SuperSession STC data sets must be properly protected.'
  desc 'CL/SuperSession STC data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-       SENSITVE.RPT(KLSSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-       PDI(ZCLS0001)

Verify that the accesses to the CL/SuperSession STC data sets are properly restricted. If the following guidance is true, this is not a finding.

___       The TSS data set access authorizations restrict READ access to auditors and authorized users.

___       The TSS data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___       The TSS data set rules for the data sets does not restrict WRITE and/or greater access to the product STC(s) and/or batch job(s).'
  desc 'fix', 'Ensure that WRITE and/or greater access to CL/SuperSession STC data sets are limited to system programmers and CL/SuperSession STC only. Read access can be given to auditors and authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged. He will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented he will work with the ISSO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product’s installation guide and can be site specific. 

The following are an example of data sets to be protected:
SYS3.OMEGAMON.RLSNAF
SYS3.OMEGAMON.RLSNAM
SYS3.OMEGAMON.RLSTDB
SYS3.OMEGAMON.RLSVLOG

The following commands are provided as an example for implementing dataset controls: 

TSS PERMIT(syspaudt) DSN(sys3.omegamon.rlsnaf) ACCESS(ALL)
TSS PERMIT(kls) DSN(sys3.omegamon.rlsnaf) ACCESS(ALL)
TSS PERMIT(audtaudt) DSN(sys3.omegamon.rlsnaf) ACCESS(READ)
TSS PERMIT(all) DSN(sys3.omegamon.rlsnaf) ACCESS(READ)

TSS PERMIT(syspaudt) DSN(sys3.omegamon.rlsnam) ACCESS(ALL)
TSS PERMIT(kls) DSN(sys3.omegamon.rlsnam) ACCESS(ALL)
TSS PERMIT(audtaudt) DSN(sys3.omegamon.rlsnam) ACCESS(READ)
TSS PERMIT(all) DSN(sys3.omegamon.rlsnam) ACCESS(READ)

TSS PERMIT(syspaudt) DSN(sys3.omegamon.rlstdb) ACCESS(ALL)
TSS PERMIT(kls) DSN(sys3.omegamon.rlstdb) ACCESS(ALL)
TSS PERMIT(audtaudt) DSN(sys3.omegamon.rlstdb) ACCESS(READ)
TSS PERMIT(all) DSN(sys3.omegamon.rlstdb) ACCESS(READ)

TSS PERMIT(syspaudt) DSN(sys3.omegamon.rlsvlog) ACCESS(ALL)
TSS PERMIT(kls) DSN(sys3.omegamon.rlsvlog) ACCESS(ALL)
TSS PERMIT(audtaudt) DSN(sys3.omegamon.rlsvlog) ACCESS(READ)
TSS PERMIT(all) DSN(sys3.omegamon.rlsvlog) ACCESS(READ)'
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for TSS'
  tag check_id: 'C-26335r519773_chk'
  tag severity: 'medium'
  tag gid: 'V-224652'
  tag rid: 'SV-224652r519775_rule'
  tag stig_id: 'ZCLST001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26323r519774_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-27098']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
