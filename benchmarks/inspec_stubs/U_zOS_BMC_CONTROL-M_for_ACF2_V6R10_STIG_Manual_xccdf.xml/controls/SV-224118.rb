control 'SV-224118' do
  title 'BMC C0NTROL-M resources must be properly defined and protected.'
  desc 'BMC CONTROL-M can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to system programmers only in greater than read authority. Resources are also granted to certain non-systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZCTM0020)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTM0020)

Verify that the accesses to resources and/or generic equivalent are properly restricted according to the requirements specified in BMC CONTROL-M Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

Note: To determine what resource class is used review the IOACLASS setting in SECPARM. The "Trigger" resources i.e., $$SECxxx (xxx is unique to the product) are defined in the FACILITY resource class

___ The ACF2 resources are defined with a default access of PREVENT.

___ The ACF2 resource access authorizations restrict access to the appropriate personnel.

___ The ACF2 resource logging requirements are specified.'
  desc 'fix', %q(Verify that the following are properly specified in the ACP.

Note: To determine what resource class is used review the IOACLASS setting in SECPARM. The "Trigger" resources i.e., $$SECxxx (xxx is unique to the product) are defined in the FACILITY resource class

(Note: The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource class, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Use BMC CONTROL-M Resources and BMC INCONTROL Resources Descriptions tables in the zOS STIG Addendum. These tables list the resources, descriptions, and access and logging requirements. Ensure the guidelines for the resources and/or generic equivalent specified in the z/OS STIG Addendum are followed.

Note: It is the responsibility of the ISSM to determine and document appropriate personnel for access in accordance with DoD 8500.1 para 18(a),(b),(c).

The following commands are provided as a sample for implementing resource controls:

$key($$ctmpnl3) type(ioa)
- uid(BMC STCs) allow
- uid(<operaudt>) allow
- uid(<pcspaudt>) allow
- uid(<syspaudt>) allow
- uid(*) prevent)
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for ACF2'
  tag check_id: 'C-25791r868142_chk'
  tag severity: 'medium'
  tag gid: 'V-224118'
  tag rid: 'SV-224118r868144_rule'
  tag stig_id: 'ZCTMA020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25779r868143_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-32058']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
