control 'SV-224445' do
  title 'CA VTAPE STC data sets will be properly protected.'
  desc 'CA VTAPE STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(VTASTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZVTA0001)

Verify that the accesses to the CA VTAPE STC data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The RACF data set rules for the data sets restricts READ access to auditors and authorized users.

___ The RACF data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel and Tape Management personnel.

___ The RACF data set rules for the data sets restricts WRITE and/or greater access to the CA VTAPE's STC(s) and/or batch user(s).

___ The RACF data set rules for the data sets specify UACC(NONE) and NOWARNING."
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to CA VTAPE STC data sets is limited to systems programmers, Tape Management personnel and/or CA VTAPE's STC(s) and/or batch user(s) only. READ access can be given to auditors and authorized users.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS3.VTAPE (data sets that are altered by the product's STCs, this can be more specific)

The following commands are provided as a sample for implementing data set controls: 

ad 'SYS3.VTAPE.**' uacc(none) owner(sys3) -
	audit(failures(read)) -
	data('Vendor DS Profile: CA VTAPE')
pe 'SYS3.VTAPE.**' id(<syspaudt> <tstcaudt> VTAPE STCs) acc(a)
pe 'SYS3.VTAPE.**' id(<tapeaudt> VTAPE STCs) acc(a)
pe 'SYS3.VTAPE.**' id(<audtaudt> authorized users) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS CA VTAPE for RACF'
  tag check_id: 'C-26122r868564_chk'
  tag severity: 'medium'
  tag gid: 'V-224445'
  tag rid: 'SV-224445r868569_rule'
  tag stig_id: 'ZVTAR001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-26110r868568_fix'
  tag 'documentable'
  tag legacy: ['SV-33828', 'V-17067']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
