control 'SV-224436' do
  title 'CA MICS Resource Management installation data sets must be properly protected.'
  desc 'CA MICS Resource Management installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(MICSRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZMIC0000)

Verify that the accesses to the CA MICS Resource Management installation data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The RACF data set access authorizations restrict READ access to all authorized users (e.g., auditors, security administrators, and MICS end users).

___ The RACF data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The RACF data set access authorizations restrict WRITE and/or greater access to MICS administrators.

___ The RACF data set access authorizations specify that all (i.e., failures and successes) WRITE and/or greater accesses are logged.

___ The RACF data set access authorizations specify UACC(NONE) and NOWARNING.'
  desc 'fix', "The ISSO will ensure WRITE and/or greater access to CA MICS Resource Management installation data sets is limited to systems programmers and MICS administrators. READ access can be given to all authorized users (e.g., auditors, security administrators, and MICS end users). All failures and successful WRITE and/or greater accesses are logged. 

The installing systems programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and, if required, that all WRITE and/or greater access is logged. The installing systems programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note:  The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS2.MICS.

The following commands are provided as a sample for implementing data set controls: 

ad 'SYS2.MICS.**' uacc(none) owner(sys2) -
	audit(success(update) failures(read)) -
	data('CA-MICS Resource Management Install DS')
pe 'SYS2.MICS.**' id(syspaudt tstcaudt micsadm) acc(a)
pe 'SYS2.MICS.**' id(audtaudt micsuser secaaudt) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS CA MICS for RACF'
  tag check_id: 'C-26113r868468_chk'
  tag severity: 'medium'
  tag gid: 'V-224436'
  tag rid: 'SV-224436r868470_rule'
  tag stig_id: 'ZMICR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26101r868469_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-49858']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
