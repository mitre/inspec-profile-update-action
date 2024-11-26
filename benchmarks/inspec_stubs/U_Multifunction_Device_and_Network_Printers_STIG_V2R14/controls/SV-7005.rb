control 'SV-7005' do
  title 'Management protocols, with the exception of HTTPS and SNMPv3, must be disabled at all times except when necessary.'
  desc 'Unneeded protocols expose the device and the network to unnecessary vulnerabilities.'
  desc 'check', "Verify that all management protocols are disabled unless approved by the organization's AO/ISSM.

Protocols may be enabled temporarily if needed to upgrade firmware or configure the device, but must be disabled immediately when this activity is completed. HTTPS and SNMPv3 may be used but must be configured in accordance with the requirements of the Network Infrastructure STIG.

If management protocols other than HTTPS and SNMPv3 are enabled unnecessarily or without AO/ISSM approval, this is a finding."
  desc 'fix', "Disable all management protocols except HTTPS and SNMPv3 unless approval has been granted by the organization's AO/ISSM."
  impact 0.5
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-2969r2_chk'
  tag severity: 'medium'
  tag gid: 'V-6783'
  tag rid: 'SV-7005r2_rule'
  tag stig_id: 'MFD02.003'
  tag gtitle: 'MFD Management Protocols'
  tag fix_id: 'F-6436r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
end
