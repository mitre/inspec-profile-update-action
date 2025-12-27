control 'SV-224319' do
  title 'IBM System Display and Search Facility (SDSF) resources must be properly defined and protected.'
  desc 'IBM System Display and Search Facility (SDSF) can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to system programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZISF0020)
- ACF2CMDS.RPT(RESOURCE) – Alternate report

Automated Analysis requiring additional analysis.
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZISF0020)

Ensure all IBM SDSF resources are properly protected according to the requirements specified in the Site Security Plan (SSP). The plan should be based on the SDSF SAF Resources table in the z/OS STIG Addendum and validated by the site ISSO. If the following guidance is true, this is not a finding.

___ The ACF2 resources and/or generic equivalent as designated in the above table are defined with a default access of NONE.

___ The ACF2 resource access authorizations restrict access to the appropriate personnel as designated in the above table.

___ The ACF2 resource logging is specified as designated in the above table.

___ The ACF2 resource access authorizations for SDSF GROUP.group-name will require additional analysis to justify access.'
  desc 'fix', 'The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resource type, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product’s installation guide and can be site-specific.)

Ensure that all IBM SDSF resources are properly protected according to the requirements specified in the Site Security Plan (SSP). The plan should be based on the SDSF SAF Resources table in the z/OS STIG Addendum and validated by the site ISSO.

Use SDSF SAF Resources and SDSF SAF Resource Descriptions tables in the zOS STIG Addendum/SSP. These tables list the resources and access requirements for IBM SDSF; ensure the following guidelines are followed:

The ACF2 resources and/or generic equivalent as designated in the above table are defined with a default access of NONE.

The ACF2 resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The ACF2 resource logging is specified as designated in the above table.

The ACF2 resource access authorizations for SDSF GROUP.group-name will require additional analysis to justify access.

The following commands are provided as a sample for implementing resource controls:

$KEY(ISFATTR) TYPE(SDS)
JOBCL.- UID(operaudt) SERVICE(READ,UPDATE) ALLOW
JOBCL.- UID(syspaudt) SERVICE(READ,UPDATE) ALLOW
- UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for ACF2'
  tag check_id: 'C-25996r840230_chk'
  tag severity: 'medium'
  tag gid: 'V-224319'
  tag rid: 'SV-224319r840232_rule'
  tag stig_id: 'ZISFA020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25984r840231_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-40818']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
