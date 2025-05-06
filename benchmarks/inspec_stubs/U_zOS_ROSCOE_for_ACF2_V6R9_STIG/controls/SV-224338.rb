control 'SV-224338' do
  title 'ROSCOE resources must be properly defined and protected.'
  desc 'ROSCOE can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality and integrity of customer data. Many utilities assign resource controls that can be granted to system programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZROS0020)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZROS0020)

Ensure that all ROSCOE resources and/or generic equivalent are properly protected according to the requirements specified in CA ROSCOE Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The ACF2 resources are defined with a default access of PREVENT.

___ The ACF2 resource access authorizations restrict access to the appropriate personnel.

___ The ACF2 resource logging is correctly specified.'
  desc 'fix', "The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resource type, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Ensure that all ROSCOE resources and/or generic equivalent are properly protected according to the requirements specified in CA ROSCOE Resources table in the z/OS STIG Addendum.

Use CA ROSCOE Resources table in the z/OS STIG Addendum. This table lists the resources, access requirements, and logging requirements for ROSCOE ensure the following guidelines are followed:

The ACF2 resources are defined with a default access of PREVENT.

The ACF2 resource access authorizations restrict access to the appropriate personnel.

The ACF2 resource logging is correctly specified.

The following commands are provided as a sample for implementing resource controls:

$KEY(rosid) TYPE(ROS)
ROSCMD.ETSO UID(*) SEVICE(READ)
ROSCMD.MONITOR.- UID(syspaudt) ALLOW
ROSCMD.MONITOR.AMS UID(syspaudt) ALLOW
ROSCMD.MONITOR.AMS UID(*) SEVICE(READ)
ROSCMD.- UID(syspaudt) ALLOW
- UID(*) PREVENT"
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for ACF2'
  tag check_id: 'C-26015r868222_chk'
  tag severity: 'medium'
  tag gid: 'V-224338'
  tag rid: 'SV-224338r868224_rule'
  tag stig_id: 'ZROSA020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26003r868223_fix'
  tag 'documentable'
  tag legacy: ['SV-21876', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
