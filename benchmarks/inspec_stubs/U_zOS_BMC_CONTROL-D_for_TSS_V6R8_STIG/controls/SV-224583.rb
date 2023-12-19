control 'SV-224583' do
  title 'BMC CONTROL-D resources must be properly defined and protected.'
  desc 'BMC CONTROL-D can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following reports produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(ZCTD0020)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTD0020)

Verify that the accesses to resources and/or generic equivalent are properly restricted according to the requirements specified in BMC CONTROL-D Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

Note: To determine what resource class is used review the IOACLASS setting in SECPARM. The "Trigger" resources i.e., $$SECxxx (xxx is unique to the product) are defined in the FACILITY resource class

___ The TSS resources are owned or DEFPROT is specified for the resource class.

___ The TSS resource access authorizations restrict access to the appropriate personnel.

___ The TSS resource logging requirements are specified.'
  desc 'fix', %q(The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

Note: To determine what resource class is used review the IOACLASS setting in SECPARM. The "Trigger" resources i.e., $$SECxxx (xxx is unique to the product) are defined in the FACILITY resource class

(Note: The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource class, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Use BMC CONTROL-D Resources and BMC INCONTROL Resources Descriptions tables in the zOS STIG Addendum. These tables list the resources, descriptions, and access and logging requirements. Ensure the guidelines for the resources and/or generic equivalent specified in the z/OS STIG Addendum are followed.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(ADMIN) IOA($$ADDNOT)
TSS PERMIT(<appsaudt>) IOA($$ADDNOT) ACC(ALL)
TSS PERMIT(<operaudt>) IOA($$ADDNOT) ACC(ALL)
TSS PERMIT(<pcspaudt>) IOA($$ADDNOT) ACC(ALL)
TSS PERMIT(<syspaudt>) IOA($$ADDNOT) ACC(ALL))
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-D for TSS'
  tag check_id: 'C-26266r868661_chk'
  tag severity: 'medium'
  tag gid: 'V-224583'
  tag rid: 'SV-224583r868663_rule'
  tag stig_id: 'ZCTDT020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26254r868662_fix'
  tag 'documentable'
  tag legacy: ['SV-32057', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
