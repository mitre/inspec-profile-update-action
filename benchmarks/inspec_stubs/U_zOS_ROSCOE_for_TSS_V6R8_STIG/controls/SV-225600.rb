control 'SV-225600' do
  title 'ROSCOE resources must be properly defined and protected.'
  desc 'ROSCOE can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality and integrity of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZROS0020)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZROS0020)

Ensure that all ROSCOE resources and/or generic equivalent are properly protected according to the requirements specified in CA ROSCOE Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The TSS resources and/or generic equivalent as designated in the above table are owned or DEFPROT is specified for the resource class.

___ The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

___ The TSS resource logging is specified as designated in the above table.'
  desc 'fix', "The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resources and/or resource prefixes identified below are examples of a possible installation. The actual resources and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Ensure that all ROSCOE resources and/or generic equivalent are properly protected according to the requirements specified in CA ROSCOE Resources table in the z/OS STIG Addendum.

Use CA ROSCOE Resources table in the z/OS STIG Addendum. This table lists the resources, access requirements, and logging requirements for ROSCOE ensure the following guidelines are followed:

The TSS resources and/or generic equivalent as designated in the above table are owned or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The TSS resource logging is specified as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(dept-acid) ROSRES(rosid)
TSS PERMIT(ALL) ROSRES(rosid.ROSCMD.ETSO) ACCESS(READ)
TSS PERMIT(syspaudt) ROSRES(rosid.ROSCMD.MONITOR.) ACCESS(ALL)
TSS PERMIT(syspaudt) ROSRES(rosid.ROSCMD.MONITOR.AMS) ACCESS(ALL)
TSS PERMIT(ALL) ROSRES(rosid.ROSCMD.MONITOR.AMS) ACCESS(READ)
TSS PERMIT(syspaudt) ROSRES(rosid.ROSCMD.) ACCESS(ALL)"
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for TSS'
  tag check_id: 'C-27300r868751_chk'
  tag severity: 'medium'
  tag gid: 'V-225600'
  tag rid: 'SV-225600r868753_rule'
  tag stig_id: 'ZROST020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-27288r868752_fix'
  tag 'documentable'
  tag legacy: ['SV-23709', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
