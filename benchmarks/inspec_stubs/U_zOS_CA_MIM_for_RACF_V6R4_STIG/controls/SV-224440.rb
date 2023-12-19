control 'SV-224440' do
  title 'CA MIM Resource Sharing STC data sets will be properly protected.'
  desc 'CA MIM Resource Sharing STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(MIMSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZMIM0001)

Verify that the accesses to the CA MIM Resource Sharing STC data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The RACF data set access authorizations restrict READ access to auditors and authorized users.

___ The RACF data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The RACF data set access authorizations restrict WRITE and/or greater access to the CA MIM Resource Sharing's STC(s) and/or batch user(s).

___ The RACF data set access authorizations for the data sets specify UACC(NONE) and NOWARNING."
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to CA MIM Resource Sharing STC data sets is limited to systems programmers and/or CA MIM Resource Sharing's STC(s) and/or batch user(s) only. Read access can be given to auditors and authorized users.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged. The installing systems programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS3.MIMGR. (Data sets that are altered by the product's STCs, this can be more specific.)

The following commands are provided as a sample for implementing data set controls: 

ad 'SYS3.MIMGR.**' uacc(none) owner(sys3) -
	audit(failures(read)) -
	data('Vendor DS Profile: CA MIM Resource Sharing')
pe 'SYS3.MIMGR.**' id(<syspaudt> <tstcaudt> CA MIM STCs) acc(a)
pe 'SYS3.MIMGR.**' id(<audtaudt> authorized users) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS CA MIM for RACF'
  tag check_id: 'C-26117r868483_chk'
  tag severity: 'medium'
  tag gid: 'V-224440'
  tag rid: 'SV-224440r868486_rule'
  tag stig_id: 'ZMIMR001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26105r868484_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-46166']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
