control 'SV-225108' do
  title 'IBM System Display and Search Facility (SDSF) resources will be properly defined and protected.'
  desc 'IBM System Display and Search Facility (SDSF) can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to system programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

-	SENSITVE.RPT(ZISF0021)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZISF0021)

Ensure that all SDSF resources are properly protected according to the requirements specified in the SDSF Server OPERCMDS Resources table in the z/OS STIG Addendum.    If the following guidance is true, this is not a finding.

___	The TSS resources and/or generic equivalent as designated in the above table are owned or DEFPROT is specified for the resource class.

___	The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

___	The TSS resource logging is specified as designated in the above table.'
  desc 'fix', 'The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

Ensure that the IBM SDSF resource access is in accordance with those outlined in SDSF Server OPERCMDS Resources table in the zOS STIG Addendum.

Use SDSF Server OPERCMDS Resources table in the zOS STIG Addendum.  These tables list the resources and access requirements for IBM SDSF; ensure the following guidelines are followed:

The TSS resources and/or generic equivalent as designated in the above table are owned or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The TSS resource logging is specified as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(dept-acid) OPERCMDS(SDSF)
TSS PERMIT(syspaudt) OPERCMDS(SDSF.MODIFY) ACCESS(CONTROL) ACTION(AUDIT)
TSS PERMIT(audtaudt) OPERCMDS(SDSF.MODIFY.DISPLAY) ACCESS(READ)
TSS PERMIT(operaudt) OPERCMDS(SDSF.MODIFY.DISPLAY) ACCESS(READ)
TSS PERMIT(syspaudt) OPERCMDS(SDSF.MODIFY.DISPLAY) ACCESS(READ)'
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for TSS'
  tag check_id: 'C-26807r467164_chk'
  tag severity: 'medium'
  tag gid: 'V-225108'
  tag rid: 'SV-225108r856994_rule'
  tag stig_id: 'ZISFT021'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26795r840205_fix'
  tag 'documentable'
  tag legacy: ['V-17982', 'SV-40752']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
