control 'SV-246881' do
  title 'The Horizon Client must not allow command line credentials.'
  desc 'The Horizon Client has a number of command line options including authentication parameters, by default. This can include a smart card PIN, if so configured by the end user. This would normally be implemented by a script, which would mean plain text sensitive authenticators sitting on disk. Hard coding of credentials of any sort, but especially smart card PINs, must be explicitly disallowed.'
  desc 'check', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Allow command line credentials".

If "Allow command line credentials" is "Not Configured" or "Enabled", this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Allow command line credentials".

Make sure the setting is "Disabled". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Client'
  tag check_id: 'C-50313r768601_chk'
  tag severity: 'medium'
  tag gid: 'V-246881'
  tag rid: 'SV-246881r768603_rule'
  tag stig_id: 'HRZC-7X-000007'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50267r768602_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
