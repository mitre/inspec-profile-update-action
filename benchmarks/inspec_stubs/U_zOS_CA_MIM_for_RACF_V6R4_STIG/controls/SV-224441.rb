control 'SV-224441' do
  title 'CA MIM Resource Sharing resources will be properly defined and protected.'
  desc 'CA MIM Resource Sharing can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(ZMIM0020)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZMIM0020)

Verify that the accesses to resources and/or generic equivalent are properly restricted according to the requirements specified in CA MIM Resource Sharing Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The RACF resources are defined with a default access of NONE.

___ The RACF resource access authorizations restrict access to the appropriate personnel.

___ The RACF resource access authorizations are defined with UACC(NONE) and NOWARNING.'
  desc 'fix', "The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resources and/or resource prefixes identified below are examples of a possible installation. The actual resources and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Use CA MIM Resource Sharing Resources table in the zOS STIG Addendum. This table list the resources, access requirements, and logging requirement for CA MIM Resource Sharing. Ensure the guidelines for the resources and/or generic equivalent specified in the z/OS STIG Addendum are followed.

Note: SAFPREFIX identifies the prefix for all resources. The default value for this keyword parameter is MIMGR. It is coded in the MIMINIT member of the data set specified in the MIMPARMS DD statement of the started task procedures.

The RACF resources as designated in the above table are defined with a default access of NONE.

The RACF resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The RACF resource rules for the resources designated in the above table specify UACC(NONE) and NOWARNING.

The following commands are provided as a sample for implementing resource controls:

RDEFINE OPERCMDS prefix.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEFINE OPERCMDES prefix.ACTIVATE UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
PERMIT prefix.ACTIVATE CLASS(OPERCMDS) ACCESS(UPDATE) ID(syspaudt)"
  impact 0.5
  ref 'DPMS Target zOS CA MIM for RACF'
  tag check_id: 'C-26118r868489_chk'
  tag severity: 'medium'
  tag gid: 'V-224441'
  tag rid: 'SV-224441r868491_rule'
  tag stig_id: 'ZMIMR020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26106r868490_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-46208']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
