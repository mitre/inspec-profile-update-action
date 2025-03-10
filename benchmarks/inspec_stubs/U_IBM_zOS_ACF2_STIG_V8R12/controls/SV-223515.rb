control 'SV-223515' do
  title 'ACF2 AUTOERAS GSO record value must be set to indicate that ACF2 is controlling the automatic physical erasure of VSAM or non VSAM data sets.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.'
  desc 'check', 'From an ACF Command screen enter:
SET CONTROL(GSO)
LIST AUTOERAS

If the GSO AUTOERAS record values conform to the following requirements, this is not a finding.

All Systems: NON-VSAM VSAM VOLS(-)'
  desc 'fix', 'Configure the AUTOERASE GSO value to indicate that ACF2 is controlling the automatic physical erasure of VSAM or non VSAM data sets.

Example:
SET C(GSO)
INSERT AUTOERAS NON-VSAM VSAM VOLS(-) 

F ACF2,REFRESH(AUTOERAS)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25188r500678_chk'
  tag severity: 'medium'
  tag gid: 'V-223515'
  tag rid: 'SV-223515r533198_rule'
  tag stig_id: 'ACF2-ES-000980'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-25176r500679_fix'
  tag 'documentable'
  tag legacy: ['SV-106839', 'V-97735']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
