control 'SV-224293' do
  title 'Compuware Abend-AID resources must be properly defined and protected.'
  desc 'Compuware Abend-AID can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to system programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZAID0020)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZAID0020)

NOTE: The Abend-AID resource class is identified in the Enterprise Common Components (ECC) STC procedure, CWPARM DD statement, member name AAVW00, using the parameter setting EXTERNAL_SECURITY_RESOURCE_CLASS.

Verify that the accesses to resources and/or generic equivalent are properly restricted according to the requirements specified in the Compuware Abend-AID Resources table in the z/OS STIG Addendum. 

If the following guidance is true, this is not a finding.

___ The ACF2 resources are defined with a default access of PREVENT.

___ The ACF2 resource access authorizations restrict access to the appropriate personnel.'
  desc 'fix', "Ensure that the following are properly specified in the ACP.

(Note: The resources and/or resource prefixes identified below are examples of a possible installation. The actual resources and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Use the Compuware Abend-AID Resources and Compuware Abend-AID Resources Descriptions tables in the zOS STIG Addendum. These tables list the resources, access requirements, and logging requirement for Compuware Abend-AID. Ensure the guidelines for the resources and/or generic equivalent specified in the z/OS STIG Addendum are followed.

Note: The Compuware Abend-AID resource class is identified in the Viewer Server's STC configuration procedure, CWPARM DD statement, member name AAVW00, using the parameter setting EXTERNAL_SECURITY_RESOURCE_CLASS. In addition, there is a parameter that identifies the prefix for all resources, which is EXTERNAL_SECURITY_PREFIX.

The ACF2 resources as designated in the above table are defined with a default access of PREVENT.

The ACF2 resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

$KEY(prefix) TYPE(resource-type)
SERVER.LOGON.FD.- UID(appdaudt) ALLOW
SERVER.LOGON.FD.- UID(appsaudt) ALLOW
SERVER.LOGON.FD.- UID(operaudt) ALLOW
SERVER.LOGON.FD.- UID(syspaudt) ALLOW
- UID(*) PREVENT"
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for ACF2'
  tag check_id: 'C-25966r868075_chk'
  tag severity: 'medium'
  tag gid: 'V-224293'
  tag rid: 'SV-224293r868077_rule'
  tag stig_id: 'ZAIDA020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25954r868076_fix'
  tag 'documentable'
  tag legacy: ['SV-44084', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
