control 'SV-224648' do
  title 'Catalog Solutions resources must be properly defined and protected.'
  desc 'Catalog Solutions can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non-systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZCSL0020)

Automated Analysis 
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCSL0020)

Ensure that all Catalogued Solutions resources and/or generic equivalents are properly protected according to the requirements specified in Catalogued Solutions Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The TSS resources and/or generic equivalent as designated in the above table are owned or DEFPROT is specified for the resource class.

___ The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

___ The TSS resource logging is specified as designated in the above table.'
  desc 'fix', "The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource class, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Ensure that all Catalogued Solutions resources and/or generic equivalents are properly protected according to the requirements specified in Catalogued Solutions Resources table in the z/OS STIG Addendum.

Use Catalog Solutions Resources table in the z/OS STIG Addendum. This table lists the resources, access requirements, and logging requirements for Catalogued Solutions. Ensure the following guidelines are followed:

The TSS resources and/or generic equivalent as designated in the above table are owned or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The TSS resource logging is specified as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(dept_acid) IBMFAC(hlq1)
TSS PERMIT(dasdaudt) IBMFAC(hlq1.hlq2.GLOBAL.DATASET) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(dasbaudt) IBMFAC(hlq1.hlq2.GLOBAL.DATASET) ACCESS(ALL) ACTION(AUDIT)
TSS PERMIT(syspaudt) IBMFAC(hlq1.hlq2.GLOBAL.DATASET) ACCESS(ALL) ACTION(AUDIT)"
  impact 0.5
  ref 'DPMS Target zOS Catalog Solutions for TSS'
  tag check_id: 'C-26331r868649_chk'
  tag severity: 'medium'
  tag gid: 'V-224648'
  tag rid: 'SV-224648r868651_rule'
  tag stig_id: 'ZCSLT020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26319r868650_fix'
  tag 'documentable'
  tag legacy: ['SV-19623', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
