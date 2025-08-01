control 'SV-246862' do
  title 'The Horizon Agent must only run allowed scripts on user disconnect.'
  desc 'The Horizon Agent has the capability to run scripts on user connect, disconnect, and reconnect. While this can be useful in setting up a user environment, in certain circumstances, the running of such scripts should be delegated to native windows capabilities where possible. These settings are powerful and can serve as a potential space for a privileged attacker to persist. By default, this setting is unconfigured. Should site require this setting, ensure it is audited and its configuration valid at all times.'
  desc 'check', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration. Double-click the "CommandsToRunOnDisconnect" setting.

If "CommandsToRunOnDisconnect" is "Not Configured" or "Disabled", this is not a finding.

Click the "Show..." button next to "Commands". If any of the listed commands are not expected, approved, and required, this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration. Double-click the "CommandsToRunOnDisconnect" setting.

Option 1:

Click the radio button next to "Disabled". Click "OK".

Option 2:

Click the "Show..." button next to "Commands". Highlight the unneeded command and press the "delete" key. Click "OK". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Agent'
  tag check_id: 'C-50294r768544_chk'
  tag severity: 'medium'
  tag gid: 'V-246862'
  tag rid: 'SV-246862r768546_rule'
  tag stig_id: 'HRZA-7X-000003'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50248r768545_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
