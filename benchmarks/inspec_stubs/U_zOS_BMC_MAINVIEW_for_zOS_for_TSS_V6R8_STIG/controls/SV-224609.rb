control 'SV-224609' do
  title 'BMC MAINVIEW resources must be properly defined and protected.'
  desc 'BMC MAINVIEW can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZMVZ0020)
- TSSCMDS.RPT(#RDT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZMVZ0020)

Verify that the accesses to resources and/or generic equivalent are properly restricted according to the requirements specified in BMC MAINVIEW Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The TSS resources are owned or DEFPROT is specified for the resource class.
 
___ The TSS resource access authorizations restrict access to the appropriate personnel.'
  desc 'fix', "The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The resource class, actual resources, and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Use BMC MAINVIEW Resources table in the zOS STIG Addendum. This table lists the resources, access requirements, and logging requirement for BMC MAINVIEW. Ensure the guidelines for the resources and/or generic equivalent specified in the z/OS STIG Addendum are followed.

The TSS resources as designated in the above table are owned and/or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(dept-acid) #BMCVIEW(BBM)
TSS PERMIT(autoaudt) #BMCVIEW(BBM.ssid.CN) ACCESS(ALL)
TSS PERMIT(dasdaudt) #BMCVIEW(BBM.ssid.CN) ACCESS(ALL)
TSS PERMIT(mqsaaudt) #BMCVIEW(BBM.ssid.CN) ACCESS(ALL)
TSS PERMIT(Mainview STCs) #BMCVIEW(BBM.ssid.CN) ACCESS(ALL)
TSS PERMIT(mvzread) #BMCVIEW(BBM.ssid.CN) ACCESS(ALL)
TSS PERMIT(mvzupdt) #BMCVIEW(BBM.ssid.CN) ACCESS(ALL)
TSS PERMIT(pcspaudt) #BMCVIEW(BBM.ssid.CN) ACCESS(ALL)
TSS PERMIT(syspaudt) #BMCVIEW(BBM.ssid.CN) ACCESS(ALL)"
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for TSS'
  tag check_id: 'C-26292r868736_chk'
  tag severity: 'medium'
  tag gid: 'V-224609'
  tag rid: 'SV-224609r868738_rule'
  tag stig_id: 'ZMVZT020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26280r868737_fix'
  tag 'documentable'
  tag legacy: ['SV-46313', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
