control 'SV-224629' do
  title 'CA MIM Resource Sharing resources will be properly defined and protected.'
  desc 'CA MIM Resource Sharing can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZMIM0020)
- TSSCMDS.RPT(#RDT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZMIM0020)

Verify that the accesses to resources and/or generic equivalent are properly restricted according to the requirements specified in CA MIM Resource Sharing Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The TSS resources are owned or DEFPROT is specified for the resource class.

___ The TSS resource access authorizations restrict access to the appropriate personnel.'
  desc 'fix', "The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resources and/or resource prefixes identified below are examples of a possible installation. The actual resources and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Use CA MIM Resource Sharing Resources table in the zOS STIG Addendum. This table list the resources, access requirements, and logging requirement for CA MIM Resource Sharing. Ensure the guidelines for the resources and/or generic equivalent specified in the z/OS STIG Addendum are followed.

Note:	SAFPREFIX identifies the prefix for all resources. The default value for this keyword parameter is MIMGR. It is coded in the MIMINIT member of the data set specified in the MIMPARMS DD statement of the started task procedures.

The TSS resources as designated in the above table are owned and/or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(dept-acid) OPERCMDS(prefix)
TSS PERMIT(syspaudt) OPERCMDS(prefix.ACTIVATE) ACCESS(UPDATE)"
  impact 0.5
  ref 'DPMS Target zOS CA MIM for TSS'
  tag check_id: 'C-26312r868730_chk'
  tag severity: 'medium'
  tag gid: 'V-224629'
  tag rid: 'SV-224629r868732_rule'
  tag stig_id: 'ZMIMT020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26300r868731_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-46209']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
