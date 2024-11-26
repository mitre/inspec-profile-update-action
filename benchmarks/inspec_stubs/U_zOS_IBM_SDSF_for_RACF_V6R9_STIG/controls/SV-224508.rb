control 'SV-224508' do
  title 'IBM System Display and Search Facility (SDSF) resources will be properly defined and protected.'
  desc 'IBM System Display and Search Facility (SDSF) can run with sensitive system privileges, and potentially can circumvent system controls.  Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data.  Many utilities assign resource controls that can be granted to system programmers only in greater than read authority.  Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(ZISF0021)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZISF0021)

Ensure that all SDSF resources are properly protected according to the requirements specified in the SDSF Server OPERCMDS Resources table in the z/OS STIG Addendum.    If the following guidance is true, this is not a finding.

___	The RACF resources and/or generic equivalent as designated in the above table are defined with a default access of NONE.

___	The RACF resource access authorizations restrict access to the appropriate personnel as designated in the above table.

___	The RACF resource logging is specified as designated in the above table.

___	The RACF resource rules for the resources designated in the above table specify UACC(NONE) and NOWARNING.'
  desc 'fix', 'The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

Ensure that the IBM SDSF resource access is in accordance with those outlined in SDSF Server OPERCMDS Resources table in the zOS STIG Addendum.

Use SDSF Server OPERCMDS Resources table in the zOS STIG Addendum.  These tables list the resources and access requirements for IBM SDSF; ensure the following guidelines are followed:

The RACF resources and/or generic equivalent as designated in the above table are defined with a default access of NONE.

The RACF resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The RACF resource logging is specified as designated in the above table.

The RACF resource rules for the resources designated in the above table specify UACC(NONE) and NOWARNING.

The following commands are provided as a sample for implementing resource controls:

RDEFINE OPERCMDS SDSF.MODIFY.** UACC(NONE) OWNER(ADMIN) –
	AUDIT(FAILURE(READ),SUCCESSFUL(UPDATE))
RDEFINE OPERCMDS SDSF.MODIFY.DISPLAY UACC(NONE) OWNER(ADMIN) –
	AUDIT(FAILURE(READ))
PERMIT SDSF.MODIFY.** CLASS(OPERCMDS) ACCESS(CONTROL) ID(syspaudt)
PERMIT SDSF.MODIFY.DISPLAY CLASS(OPERCMDS) ACCESS(READ) ID(audtaudt)
PERMIT SDSF.MODIFY.DISPLAY CLASS(OPERCMDS) ACCESS(READ) ID(operaudt)
PERMIT SDSF.MODIFY.DISPLAY CLASS(OPERCMDS) ACCESS(READ) ID(syspaudt)'
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for RACF'
  tag check_id: 'C-26191r520373_chk'
  tag severity: 'medium'
  tag gid: 'V-224508'
  tag rid: 'SV-224508r840217_rule'
  tag stig_id: 'ZISFR021'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26179r840216_fix'
  tag 'documentable'
  tag legacy: ['SV-40751', 'V-17982']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
