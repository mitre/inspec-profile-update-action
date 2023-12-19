control 'SV-224464' do
  title 'CL/SuperSession STC data sets must be properly protected.'
  desc 'CL/SuperSession STC data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(KLSSTC)

Automated Analysis:
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCLS0001)

Verify that the accesses to the CL/SuperSession STC data sets are properly restricted. If the following guidance is true, this is not a finding.

___ The RACF data set access authorizations restrict READ access to auditors and authorized users.

___ The RACF data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The RACF data set rules for the data sets does not restrict WRITE and/or greater access to the product STC(s) and/or batch job(s).

___ The RACF data set access authorizations for the data sets specify UACC(NONE) and NOWARNING.'
  desc 'fix', "Ensure that WRITE and/or greater access to CL/SuperSession STC data sets are limited to systems programmers and CL/SuperSession STC only. Read access can be given to auditors and authorized users.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged. The installing systems programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented  will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific. 

The following are an example of data sets to be protected:
SYS3.OMEGAMON.RLSNAF
SYS3.OMEGAMON.RLSNAM
SYS3.OMEGAMON.RLSTDB
SYS3.OMEGAMON.RLSVLOG

The following commands are provided as an example for implementing dataset controls: 

ad 'sys3.omegamon.rlsnaf.** uacc(none) owner(sys3) -
audit(failures(read)) -
data('Site Customized CL/Supersession VSAM')
pe 'sys3.omegamon.rlsnaf.**' id(syspaudt) acc(a)
pe 'sys3.omegamon.rlsnaf.**' id(kls) acc(a)
pe 'sys3.omegamon.rlsnaf.**' id(audtaudt) acc(r)
pe 'sys3.omegamon.rlsnaf.**' id(*) acc(r)

ad 'sys3.omegamon.rlsnam.** uacc(none) owner(sys3) -
audit(failures(read)) -
data('Site Customized CL/Supersession VSAM')
pe 'sys3.omegamon.rlsnam.**' id(syspaudt) acc(a)
pe 'sys3.omegamon.rlsnam.**' id(kls) acc(a)
pe 'sys3.omegamon.rlsnam.**' id(audtaudt) acc(r)
pe 'sys3.omegamon.rlsnam.**' id(*) acc(r)

ad 'sys3.omegamon.rlstdb.** uacc(none) owner(sys3) -
audit(failures(read)) -
data('Site Customized CL/Supersession VSAM')
pe 'sys3.omegamon.rlstdb.**' id(syspaudt) acc(a)
pe 'sys3.omegamon.rlstdb.**' id(kls) acc(a)
pe 'sys3.omegamon.rlstdb.**' id(audtaudt) acc(r)
pe 'sys3.omegamon.rlstdb.**' id(*) acc(r)

ad 'sys3.omegamon.rlsvlog.** uacc(none) owner(sys3) -
audit(failures(read)) -
data('Site Customized CL/Supersession VSAM')
pe 'sys3.omegamon.rlsvlog.**' id(syspaudt) acc(a)
pe 'sys3.omegamon.rlsvlog.**' id(kls) acc(a)
pe 'sys3.omegamon.rlsvlog.**' id(audtaudt) acc(r)
pe 'sys3.omegamon.rlsvlog.**' id(*) acc(r)"
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for RACF'
  tag check_id: 'C-26141r868331_chk'
  tag severity: 'medium'
  tag gid: 'V-224464'
  tag rid: 'SV-224464r868333_rule'
  tag stig_id: 'ZCLSR001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26129r868332_fix'
  tag 'documentable'
  tag legacy: ['SV-27097', 'V-17067']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
