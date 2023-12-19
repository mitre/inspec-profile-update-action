control 'SV-224117' do
  title 'BMC CONTROL-M User/Application JCL data sets must be properly protected.'
  desc 'BMC CONTROL-M User/Application JCL data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTMJCL)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTM0003)

Verify that the accesses to the BMC CONTROL-M User/Application JCL data sets are limited to only those who require access to perform their job duties. If the following guidance is true, this is not a finding.

___ The ACF2 data set access authorizations restrict READ access to auditors, automated batch user(s), BMC user(s), and operations.

___ The ACF2 data set access authorizations restrict WRITE and/or greater access to BMC CONTROL-M administrators and systems programming personnel.

___ The ACF2 data set access authorizations restrict UPDATE access to the Production Control and Scheduling personnel (both domain level and Application level) and BMC STCs and/or batch users. Accesses must be reviewed and approved by the ISSO based on a documented need to perform job duties. Application (external users) will not have access to internal/site data sets.

Note: Update access of the site's DASD Administrator Batch Processing JCL and Procedures must be limited to only the LPAR level DASD Administrators. Update access of the site's (LPAR Level) IA (Security) administrative batch processing JCL and Procedures must be limited to only the LPAR LEVEL ISSO/ISSM Team. It is recommended that multiple data sets be created, one of which that contains JCL and Procedures that are considered restricted and this data set be authorized to those users with justification to maintain and run these restricted JCL and Procedures."
  desc 'fix', "Ensure that WRITE and/or greater access to BMC CONTROL-M User/Application JCL data sets are limited to systems programmers and/or BMC administrators only. UPDATE access can be given to the production control and scheduling personnel (both domain level and Application level) and BMC STCs and/or batch users. READ access can be given to auditors, automated batch user(s), BMC users, and operations. Access will be based on a documented need to know requirement. Application (external users) will not have access to internal/site data sets.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. 

The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
IOA.

The following commands are provided as a sample for implementing data set controls: 

$KEY(IOA)
- UID(<bmcadmin>) R(A) W(A) A(A) E(A)
- UID(<syspaudt>) R(A) W(A) A(A) E(A)
- UID(<tstcaudt>) R(A) W(A) A(A) E(A)
- UID(CONTDAY) R(A) W(A) E(A)
- UID(CONTROLM) R(A) W(A) E(A)
- UID(<dpcsaudt>) R(A) W(A) E(A)
- UID(<pcspaudt>) R(A) W(A) E(A)
- UID(<audtaudt>) R(A) E(A)
- UID(<autoaudt>) R(A) E(A)
- UID(<bmcuser>) R(A) E(A)
- UID(<operaudt>) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for ACF2'
  tag check_id: 'C-25790r868139_chk'
  tag severity: 'medium'
  tag gid: 'V-224117'
  tag rid: 'SV-224117r868141_rule'
  tag stig_id: 'ZCTMA003'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25778r868140_fix'
  tag 'documentable'
  tag legacy: ['SV-32215', 'V-17072']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
