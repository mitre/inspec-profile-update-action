control 'SV-224392' do
  title 'BMC CONTROL-D user data sets must be properly protected.'
  desc 'BMC CONTROL-D User data sets, CDAM and Repository, have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTMUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTD0002)

Verify that the accesses to the BMC CONTROL-D User data sets are properly restricted. If the following guidance is true, this is not a finding.

___ The RACF data set access authorizations restrict READ access to auditors.

___ The RACF data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The RACF data set access authorizations restrict WRITE and/or greater access to the BMC STCs and/or batch users.

___ The RACF data set access authorizations restrict UPDATE access to centralized and decentralized security personnel, and/or CONTROL-D end users.

___ The RACF data set access authorizations specify UACC(NONE) and NOWARNING.'
  desc 'fix', "The ISSO must ensure that WRITE and/or greater access to BMC CONTROL-D User data sets are limited to systems programmers and BMC STCs and/or batch users. Additionally, UPDATE access can be given to centralized and decentralized security personnel, and BMC users. READ access can be given to auditors.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented he will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS3.IOA.*.CTDR.
CTRUSR.
CTDSRV.
CTDJB1.

The following commands are provided as a sample for implementing data set controls: 

ad 'SYS3.IOA.*.CTDR.**' uacc(none) owner(sys3) -
audit(failures(read)) -
data('BMC CONTROL-D Repository DS')
pe 'SYS3.IOA.*.CTDR.**' id(syspaudt tstcaudt BMC STCs) acc(a)
pe 'SYS3.IOA.*.CTDR.**' id(bmcuser) acc(u)
pe 'SYS3.IOA.*.CTDR.**' id(secaaudt secdaudt) acc(u)
pe 'SYS3.IOA.*.CTDR.**' id(audtaudt) acc(r)

ad 'CTRUSR.**' uacc(none) owner(CTRUSR) -
audit(failures(read)) -
data('BMC CONTROL-D CDAM DS')
pe 'CTRUSR.**' id(syspaudt tstcaudt BMC STCs) acc(a)
pe 'CTRUSR.**' id(bmcuser) acc(u)
pe 'CTRUSR.**' id(secaaudt secdaudt) acc(u)
pe 'CTRUSR.**' id(audtaudt) acc(r)

ad 'CTDSRV.**' uacc(none) owner(CTDSRV) -
audit(failures(read)) -
data('BMC CONTROL-D CDAM DS')
pe 'CTDSRV.**' id(syspaudt tstcaudt BMC STCs) acc(a)
pe 'CTDSRV.**' id(bmcuser) acc(u)
pe 'CTDSRV.**' id(secaaudt secdaudt) acc(u)
pe 'CTDSRV.**' id(audtaudt) acc(r)

ad 'CTDJB1.**' uacc(none) owner(CTDJB1) -
audit(failures(read)) -
data('BMC CONTROL-D CDAM DS')
pe 'CTDJB1.**' id(syspaudt tstcaudt BMC STCs) acc(a)
pe 'CTDJB1.**' id(bmcuser) acc(u)
pe 'CTDJB1.**' id(secaaudt secdaudt) acc(u)
pe 'CTDJB1.**' id(audtaudt) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-D for RACF'
  tag check_id: 'C-26069r518677_chk'
  tag severity: 'medium'
  tag gid: 'V-224392'
  tag rid: 'SV-224392r868350_rule'
  tag stig_id: 'ZCTDR002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26057r868349_fix'
  tag 'documentable'
  tag legacy: ['V-21592', 'SV-32163']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
