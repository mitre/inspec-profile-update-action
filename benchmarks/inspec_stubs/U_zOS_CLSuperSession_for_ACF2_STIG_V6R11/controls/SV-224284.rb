control 'SV-224284' do
  title 'CL/SuperSession Install data sets must be properly protected.'
  desc 'CL/SuperSession Install data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)       Refer to the following report produced by the Data Set and Resource Data Collection:

-       SENSITVE.RPT(KLSRPT) 

Automated Analysis:
Refer to the following report produced by the Data Set and Resource Data Collection:

-       PDI(ZCLS0000)

b)       Verify that access to the CL/SuperSession Install data sets are properly restricted.

___       The ACF2 data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___       The ACF2 data set rules for the data sets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)       If all of the above are untrue, there is NO FINDING.

d)       If any of the above is true, this is a FINDING.'
  desc 'fix', 'Ensure that update and allocate access to CL/SuperSession install data sets are limited to system programmers only, and all update and allocate access is logged. Auditors should have READ access.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the ISSO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

The following dataset are an example of data sets to be protected: 
SYS2.OMEGAMON
SYS2.OMEGAMON.V-.TLSLOAD
SYS2.OMEGAMON.V-.TLVLOAD
SYS3.OMEGAMON
SYS3.OMEGAMON.RLSLOAD

The following commands are provided as an example for implementing dataset controls: 

$KEY(SYS2)
OMEGAMON.- UID(syspaudt) R(A) W(L) A(L) E(A)
OMEGAMON.V-.TLSLOAD UID(syspaudt) R(A) W(L) A(L) E(A) 
OMEGAMON.V-.TLVLOAD UID(syspaudt) R(A) W(L) A(L) E(A) 
OMEGAMON.- UID(audtaudt) R(A) E(A)

$KEY(SYS3)
OMEGAMON.- UID(syspaudt) R(A) W(L) A(L) E(A)
OMEGAMON.RLSLOAD UID(syspaudt) R(A) W(L) A(L) E(A) 
OMEGAMON.- UID(audtaudt) R(A) E(A)'
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for ACF2'
  tag check_id: 'C-25957r519722_chk'
  tag severity: 'medium'
  tag gid: 'V-224284'
  tag rid: 'SV-224284r519724_rule'
  tag stig_id: 'ZCLSA000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25945r519723_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-27073']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
