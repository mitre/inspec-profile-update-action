control 'SV-224411' do
  title 'BMC CONTROL-O STC data sets must be properly protected.'
  desc 'BMC CONTROL-O STC data sets have the ability to use privileged functions and/or have access to sensitive data.  Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(CTOSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZCTO0001)

Verify that the accesses to the BMC CONTROL-O STC data sets are properly restricted.  If the following guidance is true, this is not a finding.

___	The RACF data set access authorizations restrict READ access to auditors, operators, and domain level production control and scheduling personnel.

___	The RACF data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___	The RACF data set access authorizations restrict UPDATE access to the BMC users and BMC STCs and/or batch users.

___	The RACF data set access authorizations specify UACC(NONE) and NOWARNING.'
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to BMC CONTROL-O STC data sets are limited to System Programmers only.  UPDATE access can be given to BMC users and the BMC STCs and/or batch users.  READ access can be given to auditors, operators, and domain level production control and scheduling personnel.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have what type of access and if required which type of access is logged.  The installing systems programmer will identify any additional groups requiring access to specific data sets, and once documented the installing systems programmer will work with the ISSO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS3.IOA.*.CTOO.**
The following commands are provided as a sample for implementing data set controls: 

ad 'SYS3.IOA.*.CTOO.**' uacc(none) owner(sys3) -
audit(failures(read)) -
data('BMC CONTROL-O Operational & Repository')
pe 'SYS3.IOA.*.CTOO.**' id(<syspaudt>) acc(a)
pe 'SYS3.IOA.*.CTOO.**' id(CONTROLO) acc(u)
pe 'SYS3.IOA.*.CTOO.**' id(<bmcuser> <bmcbatch>) acc(u)
pe 'SYS3.IOA.*.CTOO.**' id(<audtaudt>) acc(r)
pe 'SYS3.IOA.*.CTOO.**' id(<operaudt>) acc(r)
pe 'SYS3.IOA.*.CTOO.**' id(<pcspaudt>) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-O for RACF'
  tag check_id: 'C-26088r518848_chk'
  tag severity: 'medium'
  tag gid: 'V-224411'
  tag rid: 'SV-224411r518850_rule'
  tag stig_id: 'ZCTOR001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26076r518849_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-31944']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
