control 'SV-224460' do
  title 'Catalog Solutions resources must be properly defined and protected.'
  desc 'Catalog Solutions can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non-systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(ZCSL0020)

Automated Analysis 
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCSL0020)

Ensure that all Catalogued Solutions resources and/or generic equivalents are properly protected according to the requirements specified in Catalogued Solutions Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The RACF resource access authorizations restrict access to the appropriate personnel.

___ The RACF resource logging is correctly specified.

___ The RACF resource access authorizations are defined with UACC(NONE) and NOWARNING.'
  desc 'fix', "The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note:  The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource class, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Ensure that all Catalogued Solutions resources and/or generic equivalents are properly protected according to the requirements specified in Catalogued Solutions Resources table in the z/OS STIG Addendum.

Use Catalog Solutions Resources table in the z/OS STIG Addendum. This table lists the resources, access requirements, and logging requirements for Catalogued Solutions. Ensure the following guidelines are followed:

The RACF resource access authorizations restrict access to the appropriate personnel.

The RACF resource logging is correctly specified.

The RACF resource access authorizations specify UACC(NONE) and NOWARNING.

The following commands are provided as a sample for implementing resource controls:

RDEF FACILITY hlq1.** UACC(NONE) OWNER(syspaudt) AUDIT(ALL(READ))
RDEF FACILITY hlq1.hlq2.GLOBAL.DATASET.** UACC(NONE) OWNER(syspaudt) AUDIT(ALL(READ))
PERMIT hlq1.hlq2.GLOBAL.DATASET CLASS(FACILITY) ACCESS(READ) ID(dasdaudt)
PERMIT hlq1.hlq2.GLOBAL.DATASET CLASS(FACILITY) ACCESS(READ) ID(dasbaudt)
PERMIT hlq1.hlq2.GLOBAL.DATASET CLASS(FACILITY) ACCESS(READ) ID(syspaudt)"
  impact 0.5
  ref 'DPMS Target zOS Catalog Solutions for RACF'
  tag check_id: 'C-26137r868340_chk'
  tag severity: 'medium'
  tag gid: 'V-224460'
  tag rid: 'SV-224460r868342_rule'
  tag stig_id: 'ZCSLR020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26125r868341_fix'
  tag 'documentable'
  tag legacy: ['SV-19622', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
