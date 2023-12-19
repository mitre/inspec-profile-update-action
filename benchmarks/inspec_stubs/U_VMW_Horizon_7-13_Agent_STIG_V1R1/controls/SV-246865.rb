control 'SV-246865' do
  title 'The Horizon Agent must set an idle timeout.'
  desc 'Idle sessions are at increased risk of being hijacked. If a user has stepped away from their desk and is no long in positive control of their session, that session is in danger of being assumed by an attacker. Idle sessions also waste valuable datacenter resources and could potentially lead to a lack of resources for new, active users. As such, an organizationally defined idle timeout must be supplied to override the Horizon default of "never".'
  desc 'check', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration. Double-click the "Idle Time Until Disconnect (VDI)" setting.

If "Idle Time Until Disconnect (VDI)" is "Not Configured" or "Disabled", this is a finding.

In the drop-down next to "Idle Timeout", if "Never" is selected, this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Configuration. Double-click the "Idle Time Until Disconnect (VDI)" setting.

Click the radio button next to "Enabled". 

In the drop-down next to "Idle Timeout", select an appropriate, site-specific timeout that is not "Never". This is typically two hours but your configuration may vary. Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Agent'
  tag check_id: 'C-50297r768553_chk'
  tag severity: 'medium'
  tag gid: 'V-246865'
  tag rid: 'SV-246865r768555_rule'
  tag stig_id: 'HRZA-7X-000006'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50251r768554_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
