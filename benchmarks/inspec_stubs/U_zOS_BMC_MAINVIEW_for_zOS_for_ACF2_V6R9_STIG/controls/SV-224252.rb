control 'SV-224252' do
  title 'BMC MAINVIEW resources must be properly defined and protected.'
  desc 'BMC MAINVIEW can run with sensitive system privileges, and potentially can circumvent system controls.  Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data.  Many utilities assign resource controls that can be granted to system programmers only in greater than read authority.  Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

-	SENSITVE.RPT(ZMVZ0020)
-	ACF2CMDS.RPT(RESOURCE) – Alternate report

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZMVZ0020)

Verify that the accesses to resources and/or generic equivalent are properly restricted according to the requirements specified in BMC MAINVIEW Resources table in the z/OS STIG Addendum.  If the following guidance is true, this is not a finding.

___	The ACF2 resources are defined with a default access of PREVENT.

___	The ACF2 resource access authorizations restrict access to the appropriate personnel.'
  desc 'fix', 'The IAO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note:  The resource type, resources, and/or resource prefixes identified below are examples of a possible installation.  The actual resource type, resources, and/or prefixes are determined when the product is actually installed on a system through the product’s installation guide and can be site specific.)

Use BMC MAINVIEW Resources table in the zOS STIG Addendum.  This table lists the resources, access requirements, and logging requirement for BMC MAINVIEW.  Ensure the guidelines for the resource type, resources, and/or generic equivalent specified in the z/OS STIG Addendum are followed.

The ACF2 resources as designated in the above table are defined with a default access of PREVENT.

The ACF2 resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

$KEY(BBM) TYPE(BMV)
ssid.CN UID(autoaudt) ALLOW
ssid.CN UID(dasdaudt) ALLOW
ssid.CN UID(mqsaaudt) ALLOW
ssid.CN UID(Mainview STCs) ALLOW
ssid.CN UID(mvzread) ALLOW
ssid.CN UID(mvzupdt) ALLOW
ssid.CN UID(pcspaudt) ALLOW
ssid.CN UID(syspaudt) ALLOW
- UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for ACF2'
  tag check_id: 'C-25925r518965_chk'
  tag severity: 'medium'
  tag gid: 'V-224252'
  tag rid: 'SV-224252r518967_rule'
  tag stig_id: 'ZMVZA020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25913r518966_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-46311']
  tag cci: ['CCI-002234', 'CCI-000035']
  tag nist: ['AC-6 (9)', 'AC-4 (11)']
end
