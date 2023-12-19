control 'SV-246879' do
  title 'The Horizon Client must require TLS connections.'
  desc 'In older versions of Horizon, before 5.0, remote desktop connections could be established without TLS encryption. In order to protect data-in-transit when potentially connecting to very old Horizon servers, TLS tunnels must be mandated. The default configuration attempts TLS but will fall back to no encryption if it is not supported. This must be corrected and maintained over time.'
  desc 'check', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Enable SSL encrypted framework channel".

If "Enable SSL encrypted framework channel" is set to "Disabled" or "Not Configured", this is a finding.

In the dropdown beneath "Enable SSL encrypted framework channel", if "Enforce" is not selected, this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Enable SSL encrypted framework channel".

Make sure the setting is "Enabled".

In the dropdown beneath "Enable SSL encrypted framework channel", select "Enforce". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Client'
  tag check_id: 'C-50311r768595_chk'
  tag severity: 'medium'
  tag gid: 'V-246879'
  tag rid: 'SV-246879r768597_rule'
  tag stig_id: 'HRZC-7X-000005'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50265r768596_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
