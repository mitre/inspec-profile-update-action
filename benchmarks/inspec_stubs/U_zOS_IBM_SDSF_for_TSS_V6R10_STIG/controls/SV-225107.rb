control 'SV-225107' do
  title 'IBM System Display and Search Facility (SDSF) resources will be properly defined and protected.'
  desc 'IBM System Display and Search Facility (SDSF) can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non-systems personnel with read-only authority.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZISF0020)

Automated Analysis requiring additional analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZISF0020)

Ensure that all IBM System Display and Search Facility (SDSF) resources are properly protected according to the requirements specified in SDSF SAF Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The TSS resources and/or generic equivalent as designated in the above table are owned or DEFPROT is specified for the resource class.

___ The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

___ The TSS resource logging is specified as designated in the above table.

___ The TSS resource access authorizations for SDSF GROUP.group-name will require additional analysis to justify access.'
  desc 'fix', "ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The resource class, actual resources, and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site-specific.)

Ensure all IBM SDSF resources are properly protected according to the requirements specified in the SSP. The plan should be based on the SDSF SAF Resources table in the z/OS STIG Addendum and validated by the site ISSO. 

Use SDSF SAF Resources and SDSF SAF Resource Descriptions tables in the zOS STIG Addendum/SSP. These tables list the resources and access requirements for IBM SDSF; ensure the following guidelines are followed:

The TSS resources and/or generic equivalent as designated in the table above are owned or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the table above.

The TSS resource logging is specified as designated in the table above.

The TSS resource access authorizations for SDSF GROUP.group-name will require additional analysis to justify access.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(dept-acid) SDSF(ISFATTR)
TSS PERMIT(operaudt) SDSF(ISFATTR.JOBCL) ACCESS(UPDATE)
TSS PERMIT(syspaudt) SDSF(ISFATTR.JOBCL) ACCESS(UPDATE)"
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for TSS'
  tag check_id: 'C-26806r868715_chk'
  tag severity: 'medium'
  tag gid: 'V-225107'
  tag rid: 'SV-225107r868717_rule'
  tag stig_id: 'ZISFT020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26794r868716_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-40820']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
