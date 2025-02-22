control 'SV-224588' do
  title 'BMC CONTROL-M/Restart Archived Sysout data sets must be properly protected.'
  desc 'BMC CONTROL-M/Restart Archived Sysout data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTRUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTR0002)

Verify that the accesses to the BMC CONTROL-M/Restart Archived Sysout data sets are properly restricted. If the following guidance is true, this is not a finding.

___ The TSS data set access authorizations restrict READ access to auditors and BMC users.

___ The TSS data set access authorizations restrict WRITE and/or greater access to Production Control Scheduling personnel, scheduled batch user(s), systems programming personnel, and the BMC STCs and/or batch users.'
  desc 'fix', "Ensure that WRITE and/or greater access to BMC CONTROL-M/Restart Archived Sysout data sets are limited to production control scheduling personnel, scheduled batch users, systems programmers, and the BMC STCs and/or batch users only. READ access can be given to auditors and BMC users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. 

The installing Systems Programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
CTRSYS.

The following commands are provided as a sample for implementing data set controls: 

TSS PERMIT(<syspaudt>) DSN(CTRSYS.) ACCESS(ALL)
TSS PERMIT(CONTROLM) DSN(CTRSYS.) ACCESS(ALL)
TSS PERMIT(CONTDAY) DSN(CTRSYS.) ACCESS(ALL)
TSS PERMIT(<audtaudt>) DSN(CTRSYS.) ACCESS(READ) 
TSS PERMIT(<bmcuser>) DSN(CTRSYS.) ACCESS(READ)
TSS PERMIT(<autoaudt>) DSN(CTRSYS.) ACCESS(ALL)
TSS PERMIT(<pcspaudt>) DSN(CTRSYS.) ACCESS(ALL)"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M Restart for TSS'
  tag check_id: 'C-26271r868691_chk'
  tag severity: 'medium'
  tag gid: 'V-224588'
  tag rid: 'SV-224588r868693_rule'
  tag stig_id: 'ZCTRT002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26259r868692_fix'
  tag 'documentable'
  tag legacy: ['SV-32220', 'V-21592']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
