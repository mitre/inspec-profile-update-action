control 'SV-246864' do
  title 'The Horizon Agent must check the entire chain when validating certificates.'
  desc 'Any time the Horizon Agent establishes an outgoing TLS connection, it verifies the server certificate revocation status. By default, it verifies all intermediates but not the root. DoD policy requires full path validation, thus this default behavior needs to be changed.'
  desc 'check', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Common Configuration >> Security Configuration. Double-click the "Type of certificate revocation check" setting.

If "Type of certificate revocation check" is "Not Configured" or "Disabled", this is a finding.

In the drop-down under "Type of certificate revocation check", if "WholeChain" is not selected, this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Common Configuration >> Security Configuration. Double-click the "Type of certificate revocation check" setting.

Make sure the setting is "Enabled".

In the drop-down under "Type of certificate revocation check", select "WholeChain". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Agent'
  tag check_id: 'C-50296r768550_chk'
  tag severity: 'medium'
  tag gid: 'V-246864'
  tag rid: 'SV-246864r768552_rule'
  tag stig_id: 'HRZA-7X-000005'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50250r768551_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
