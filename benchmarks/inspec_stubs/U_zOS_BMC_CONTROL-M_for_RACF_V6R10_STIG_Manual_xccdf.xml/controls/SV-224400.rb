control 'SV-224400' do
  title 'BMC CONTROL-M User/Application JCL data sets must be properly protected.'
  desc 'BMC CONTROL-M User/Application JCL data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTMJCL)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTM0003)

Verify that the accesses to the BMC CONTROL-M User/Application JCL data sets are limited to only those who require access to perform their job duties. If the following guidance is true, this is not a finding.

___ The RACF data set access authorizations restrict READ access to auditors, automated batch user(s), BMC user(s), and operations.

___ The RACF data set access authorizations restrict WRITE and/or greater access to BMC CONTROL-M administrators and systems programming personnel.

___ The RACF data set access authorizations restrict UPDATE access to the Production Control and Scheduling personnel (both domain level and Application level) and BMC STCs and/or batch users. Accesses must be reviewed and approved by the ISSO based on a documented need to perform job duties. Application (external users) will not have access to internal/site data sets. 

Note: Update or greater access of the site's DASD Administrator Batch Processing JCL and Procedures must be limited to only the LPAR level DASD Administrators. Update or greater access of the site's (LPAR Level) IA (Security) administrative batch processing JCL and Procedures must be limited to only the LPAR LEVEL ISSO/ISSM Team. It is recommended that multiple data sets be created, one of which that contains JCL and Procedures that are considered restricted and this data set be authorized to those users with justification to maintain and run these restricted JCL and Procedures.

___ The RACF data set access authorizations specify UACC(NONE) and NOWARNING."
  desc 'fix', "Ensure that update and alter access to BMC CONTROL-M User/Application JCL data sets are limited to BMC CONTROL-M administrators only. Update access can be given to the Production Control and Scheduling personnel and/or BMC CONTROL-M's STC(s) and/or BMC CONTROL-M's batch user(s). Read access can be given to auditors and automated batch user(s).

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. 

The installing Systems Programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
IOA.**

The following commands are provided as a sample for implementing data set controls: 

ad 'IOA.**' uacc(none) owner(IOA) -
	data('ControlM User Datasets')
pe 'IOA.**' id(<syspaudt>) acc(a)
pe 'IOA.**' id(<audtaudt> <autoaudt>) acc(r)
pe 'IOA.**' id(<bmcuser> <bmcbatch> <operaudt> <pcspaudt>) acc(r)
pe 'IOA.**' id(CONTROLM CONTDAY) acc(r)

setr generic(dataset) refresh"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for RACF'
  tag check_id: 'C-26077r868364_chk'
  tag severity: 'medium'
  tag gid: 'V-224400'
  tag rid: 'SV-224400r868368_rule'
  tag stig_id: 'ZCTMR003'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26065r868367_fix'
  tag 'documentable'
  tag legacy: ['V-17072', 'SV-32216']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
