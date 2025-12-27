control 'SV-246875' do
  title 'The Horizon Client must not send anonymized usage data.'
  desc 'By default, the Horizon Client collects anonymized data from the client systems to help improve software and hardware compatibility. To eliminate any possibility of sensitive DoD configurations being known to unauthorized parties, even when anonymized, this setting must be disabled.'
  desc 'check', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration. Double-click the "Allow data sharing" setting.

If "Allow data sharing" is set to "Enabled" or "Not Configured", this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration. Double-click the "Allow data sharing" setting.

Make sure the setting is "Disabled". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Client'
  tag check_id: 'C-50307r768583_chk'
  tag severity: 'medium'
  tag gid: 'V-246875'
  tag rid: 'SV-246875r768585_rule'
  tag stig_id: 'HRZC-7X-000001'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50261r768584_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
