control 'SV-224425' do
  title 'BMC MAINVIEW resources must be properly defined and protected.'
  desc 'BMC MAINVIEW can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(ZMVZ0020)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZMVZ0020)

Verify that the accesses to resources and/or generic equivalent are properly restricted according to the requirements specified in BMC MAINVIEW Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The RACF resources are defined with a default access of NONE.

___ The RACF resource access authorizations restrict access to the appropriate personnel.

___ The RACF resource access authorizations are defined with UACC(NONE) and NOWARNING.'
  desc 'fix', "The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource class, resources, and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Use BMC MAINVIEW Resources table in the zOS STIG Addendum. This table lists the resources, access requirements, and logging requirement for BMC MAINVIEW. Ensure the guidelines for the resources and/or generic equivalent specified in the z/OS STIG Addendum are followed.

The RACF resources as designated in the above table are defined with a default access of NONE.

The RACF resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The RACF resource rules for the resources designated in the above table specify UACC(NONE) and NOWARNING.

The following commands are provided as a sample for implementing resource controls:

RDEFINE #BMCVIEW BBM.ssid.CN UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
PERMIT BBM.ssid.CN CLASS(#BMCVIEW) ACCESS(ALTER) ID(autoaudt)
PERMIT BBM.ssid.CN CLASS(#BMCVIEW) ACCESS(ALTER) ID(dasdaudt)
PERMIT BBM.ssid.CN CLASS(#BMCVIEW) ACCESS(ALTER) ID(mqsaaudt)
PERMIT BBM.ssid.CN CLASS(#BMCVIEW) ACCESS(ALTER) ID(Mainview STCs)
PERMIT BBM.ssid.CN CLASS(#BMCVIEW) ACCESS(ALTER) ID(mvzread)
PERMIT BBM.ssid.CN CLASS(#BMCVIEW) ACCESS(ALTER) ID(mvzupdt)
PERMIT BBM.ssid.CN CLASS(#BMCVIEW) ACCESS(ALTER) ID(pcspaudt)
PERMIT BBM.ssid.CN CLASS(#BMCVIEW) ACCESS(ALTER) ID(syspaudt)"
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for RACF'
  tag check_id: 'C-26102r868507_chk'
  tag severity: 'medium'
  tag gid: 'V-224425'
  tag rid: 'SV-224425r868512_rule'
  tag stig_id: 'ZMVZR020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26090r868510_fix'
  tag 'documentable'
  tag legacy: ['SV-46312', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
