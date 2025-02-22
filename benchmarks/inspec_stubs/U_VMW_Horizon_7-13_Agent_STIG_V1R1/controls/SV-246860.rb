control 'SV-246860' do
  title 'The Horizon Agent must require TLS connections.'
  desc 'The Horizon Agent has the capability to be backward compatible with legacy clients, circa View 5.2, which do not support newer TLS connections. By default, the agent can fall back to this non-TLS mode when being accessed by a legacy client. The Horizon Agent must be configured to not support these legacy clients and enforce TLS connections as mandatory.'
  desc 'check', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Security. Double-click the "Accept SSL encrypted framework channel" setting.

If "Accept SSL encrypted framework channel" is not "Enabled" and set to "Enforce", this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware View Agent Configuration >> Agent Security. Double-click the "Accept SSL encrypted framework channel" policy.

Make sure the policy is "Enabled". Choose "Enforce" from the drop-down. Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Agent'
  tag check_id: 'C-50292r768538_chk'
  tag severity: 'medium'
  tag gid: 'V-246860'
  tag rid: 'SV-246860r768540_rule'
  tag stig_id: 'HRZA-7X-000001'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50246r768539_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
