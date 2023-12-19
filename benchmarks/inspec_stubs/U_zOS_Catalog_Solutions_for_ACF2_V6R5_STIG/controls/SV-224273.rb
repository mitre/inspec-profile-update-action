control 'SV-224273' do
  title 'Catalog Solutions resources must be properly defined and protected.'
  desc 'Catalog Solutions can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to system programmers only in greater than read authority. Resources are also granted to certain non-systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZCSL0020)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCSL0020)

Ensure that all Catalog Solutions resources and/or generic equivalents are properly protected according to the requirements specified in Catalog Solutions Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The ACF2 resources are defined with a default access of PREVENT.

___ The ACF2 resource access authorizations restrict access to the appropriate personnel.

___ The ACF2 resource logging is correctly specified.'
  desc 'fix', "The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resource type, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Ensure that all Catalog Solutions resources and/or generic equivalent are properly protected according to the requirements specified in Catalog Solutions Resources table in the z/OS STIG Addendum.

Use Catalog Solutions Resources table in the z/OS STIG Addendum. This table lists the resources, access requirements, and logging requirements for Catalogued Solutions. Ensure the following guidelines are followed:

The ACF2 resources are defined with a default access of PREVENT.

The ACF2 resource access authorizations restrict access to the appropriate personnel.

The ACF2 resource logging is correctly specified.

The following commands are provided as a sample for implementing resource controls:

$KEY(hlq1) TYPE(FAC)
hlq2.GLOBAL.DATASET UID(dasdaudt) LOG
hlq2.GLOBAL.DATASET UID(dasbaudt) LOG
hlq2.GLOBAL.DATASET UID(syspaudt) LOG
hlq2.GLOBAL.DATASET UID(*) PREVENT
- UID(*) PREVENT"
  impact 0.5
  ref 'DPMS Target zOS Catalog Solutions for ACF2'
  tag check_id: 'C-25946r868116_chk'
  tag severity: 'medium'
  tag gid: 'V-224273'
  tag rid: 'SV-224273r868118_rule'
  tag stig_id: 'ZCSLA020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25934r868117_fix'
  tag 'documentable'
  tag legacy: ['SV-19621', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
