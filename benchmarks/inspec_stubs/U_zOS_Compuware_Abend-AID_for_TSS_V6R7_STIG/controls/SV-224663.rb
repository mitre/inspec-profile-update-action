control 'SV-224663' do
  title 'Compuware Abend-AID resources must be properly defined and protected.'
  desc 'Compuware Abend-AID can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZAID0020)
- TSSCMDS.RPT(#RDT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZAID0020)

Note: The Abend-AID resource class is identified in the Enterprise Common Components (ECC) STC procedure, CWPARM DD statement, member name AAVW00, using the parameter setting EXTERNAL_SECURITY_RESOURCE_CLASS.

Verify that the accesses to resources and/or generic equivalent are properly restricted according to the requirements specified in Compuware Abend-AID Resources table in the z/OS STIG Addendum. 

If the following guidance is true, this is not a finding.

___ The TSS resources are owned or DEFPROT is specified for the resource class.

___ The TSS resource access authorizations restrict access to the appropriate personnel.'
  desc 'fix', "Ensure that the following are properly specified in the ACP.

(Note: The resources and/or resource prefixes identified below are examples of a possible installation. The actual resources and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Use Compuware Abend-AID Resources and Compuware Abend-AID Resources Descriptions tables in the zOS STIG Addendum. These tables list the resources, descriptions, and access and logging requirements. Ensure the guidelines for the resources and/or generic equivalent specified in the z/OS STIG Addendum are followed.

Note: The Compuware Abend-AID resource class is identified in the Viewer Server's STC configuration procedure, CWPARM DD statement, member name AAVW00, using the parameter setting EXTERNAL_SECURITY_RESOURCE_CLASS. In addition, there is a parameter that identifies the prefix for all resources, which is EXTERNAL_SECURITY_PREFIX.


The TSS resources as designated in the above table are owned and/or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(dept-acid) resource-class(prefix)
TSS PERMIT(appdaudt) res-class(prefix.SERVER.LOGON.FD.) ACCESS(ALL)
TSS PERMIT(appsaudt) res-class(prefix.SERVER.LOGON.FD.) ACCESS(ALL)
TSS PERMIT(operaudt) res-class(prefix.SERVER.LOGON.FD.) ACCESS(ALL)
TSS PERMIT(syspaudt) res-class(prefix.SERVER.LOGON.FD.) ACCESS(ALL)"
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for TSS'
  tag check_id: 'C-26346r868609_chk'
  tag severity: 'medium'
  tag gid: 'V-224663'
  tag rid: 'SV-224663r868611_rule'
  tag stig_id: 'ZAIDT020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26334r868610_fix'
  tag 'documentable'
  tag legacy: ['SV-44086', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
