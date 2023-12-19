control 'SV-246877' do
  title 'The Horizon Client must not show the Log in as current user option.'
  desc 'The Horizon Connection Server STIG disabled the "Log in as current user" option, for reasons described there. Displaying this option and allowing users to select it would lead to unnecessary confusion and therefore must be disabled.'
  desc 'check', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Display option to Log in as current user".

If "Display option to Log in as current user" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Horizon Client Configuration >> Security Settings. Double-click "Display option to Log in as current user".

Make sure the setting is "Disabled". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Client'
  tag check_id: 'C-50309r768589_chk'
  tag severity: 'medium'
  tag gid: 'V-246877'
  tag rid: 'SV-246877r768591_rule'
  tag stig_id: 'HRZC-7X-000003'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50263r768590_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
