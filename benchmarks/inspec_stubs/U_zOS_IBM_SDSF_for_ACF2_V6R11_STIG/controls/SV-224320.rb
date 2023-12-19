control 'SV-224320' do
  title 'IBM System Display and Search Facility (SDSF) resources will be properly defined and protected.'
  desc 'IBM System Display and Search Facility (SDSF) can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to system programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZISF0021)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZISF0021)

Ensure that all SDSF resources are properly protected according to the requirements specified in the SDSF Server OPERCMDS Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The ACF2 resources and/or generic equivalent as designated in the above table are defined with a default access of NONE.

___ The ACF2 resource access authorizations restrict access to the appropriate personnel as designated in the above table.

___ The ACF2 resource logging is specified as designated in the above table.'
  desc 'fix', 'The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

Ensure that the IBM SDSF resource access is in accordance with those outlined in SDSF Server OPERCMDS Resources table in the zOS STIG Addendum.

Use SDSF Server OPERCMDS Resources table in the zOS STIG Addendum. These tables list the resources and access requirements for IBM SDSF; ensure the following guidelines are followed:

The ACF2 resources and/or generic equivalent as designated in the above table are defined with a default access of NONE.

The ACF2 resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The ACF2 resource logging is specified as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

$KEY(SDSF) TYPE(OPR)
MODIFY.DISPLAY UID(audtaudt) SERVICE(READ)
MODIFY.DISPLAY UID(operaudt) SERVICE(READ)
MODIFY.DISPLAY UID(syspaudt) SERVICE(READ)
MODIFY.- UID(syspaudt) SERVICE(READ,UPDATE,DELETE) LOG
- UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for ACF2'
  tag check_id: 'C-25997r868184_chk'
  tag severity: 'medium'
  tag gid: 'V-224320'
  tag rid: 'SV-224320r868186_rule'
  tag stig_id: 'ZISFA021'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25985r868185_fix'
  tag 'documentable'
  tag legacy: ['SV-40749', 'V-17982']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
