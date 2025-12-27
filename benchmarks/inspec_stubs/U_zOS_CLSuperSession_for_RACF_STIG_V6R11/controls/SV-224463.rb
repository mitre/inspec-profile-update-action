control 'SV-224463' do
  title 'CL/SuperSession Install data sets must be properly protected.'
  desc 'CL/SuperSession Install data sets provide the capability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'a)       Refer to the following report produced by the Data Set and Resource Data Collection:

-       SENSITVE.RPT(KLSRPT) 

Automated Analysis:
Refer to the following report produced by the Data Set and Resource Data Collection:

-       PDI(ZCLS0000)

b)       Verify that access to the CL/SuperSession Install data sets are properly restricted.

___       The RACF data set rules for the data sets does not restrict UPDATE and/or ALTER access to systems programming personnel.

___       The RACF data set rules for the data sets does not specify that all (i.e., failures and successes) UPDATE and/or ALTER access will be logged.

c)       If all of the above are untrue, there is NO FINDING.

d)       If any of the above is true, this is a FINDING.'
  desc 'fix', "Ensure that update and allocate access to CL/SuperSession install data sets are limited to system programmers only and all update and allocate access is logged. Auditors should be granted READ access.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. He will identify if any additional groups have update access for specific data sets, and once documented he will work with the ISSO to see that they are properly restricted to the ACP (Access Control Program ) active on the system.

The following dataset are an example of data sets to be protected: 
sys2.omegamon.** /* product datasets */
sys2.omegamon.*.tlsload.** 
sys2.omegamon.*.tlvload.** 
sys3.omegamon.**
sys3.omegamon.rlsload.**

The following commands are provided as an example for implementing dataset controls: 

ad 'sys2.omegamon.**' uacc(none) owner(sys2) -
audit(success(update) failures(read) -
data('vendor DS Profile CL/Supersession') 
pe 'sys2.omegamon.**' id(syspaudt) acc(a) 
pe 'sys2.omegamon.**' id(audtaudt) 
ad 'sys2.omegamon.*.tlsload.**' uacc(none) owner(sys2) -
audit(success(update) failures(read) -
data('vendor DS fully qualified apf Profile CL/Supersession') 
pe 'sys2.omegamon.*.tlsload.**' id(syspaudt) acc(a)
pe 'sys2.omegamon.*.tlsload.**' id(audtaudt) ad 'sys2.omegamon.*.tlvload.**' uacc(none) owner(sys2) -
audit(success(update) failures(read) - 
data('vendor DS fully qualified apf Profile CL/Supersession') 
pe 'sys2.omegamon.*.tlvload.**' id(syspaudt) acc(a) 
pe 'sys2.omegamon.*.tlvload.**' id(audtaudt) 
ad 'sys3.omegamon.**' uacc(none) owner(sys3) -
audit(success(update) failures(read) -
data('vendor DS Profile CL/Supersession') 
pe 'sys3.omegamon.**' id(syspaudt) acc(a) 
pe 'sys3.omegamon.**' id(audtaudt) 
ad 'sys3.omegamon.rlsload.**' uacc(none) owner(sys3) -
audit(success(update) failures(read) -
data('site DS fully qualified apf Profile CL/Supersession') 
pe 'sys3.omegamon.rlsload.**' id(syspaudt) acc(a) 
pe 'sys3.omegamon.rlsload.**' id(audtaudt)"
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for RACF'
  tag check_id: 'C-26140r519743_chk'
  tag severity: 'medium'
  tag gid: 'V-224463'
  tag rid: 'SV-224463r519745_rule'
  tag stig_id: 'ZCLSR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26128r519744_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-27091']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
