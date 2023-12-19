control 'SV-246872' do
  title 'The Horizon Agent must audit clipboard actions for PCoIP.'
  desc 'Data loss prevention is a primary concern for the DoD, maintaining positive control of data at all times and only allowing flows over channels that are for that explicit purpose and monitored appropriately. By default, the PCoIP protocol on the Horizon Agent will block clipboard "copy/paste" actions from the desktop to the client but allow actions from the client to the desktop. All such allowed actions must be audited for potential future forensic purposes.'
  desc 'check', 'Ensure the pcoip.admx template is added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> PCoIP Session Variables >> Overridable Administrator Settings. Double-click the "Configure clipboard audit" setting.

If "Configure clipboard audit" is "Not Configured" or "Disabled", this is a finding.

In the drop-down under "Configure clipboard audit", if "Enabled in both directions" is not selected, this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> PCoIP Session Variables >> Overridable Administrator Settings. Double-click the "Configure clipboard audit" setting.

Click the radio button next to "Enabled".

In the drop-down under "Configure clipboard audit", select "Enabled in both directions". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Agent'
  tag check_id: 'C-50304r768574_chk'
  tag severity: 'medium'
  tag gid: 'V-246872'
  tag rid: 'SV-246872r768576_rule'
  tag stig_id: 'HRZA-7X-000013'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50258r768575_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
