control 'SV-246867' do
  title 'The Horizon Agent must block server to client clipboard actions for PCoIP.'
  desc 'Data loss prevention is a primary concern for the DoD, maintaining positive control of data at all times and only allowing flows over channels that are for that explicit purpose and monitored appropriately. By default, the PCoIP protocol on the Horizon Agent will block clipboard "copy/paste" actions from the desktop to the client but allow actions from the client to the desktop. This configuration must be validated and maintained over time.'
  desc 'check', 'Ensure the pcoip.admx template is added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> PCoIP Session Variables >> Not Overridable Administrator Settings. Double-click the "Configure clipboard redirection" setting.

If "Configure clipboard redirection" is "Not Configured" or "Disabled", this is not a finding.

In the drop-down under "Configure clipboard redirection", if "Enabled server to client only" or "Enabled in both directions" is  selected, this is a finding.'
  desc 'fix', 'Ensure the vdm_agent*.admx templates are added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> PCoIP Session Variables >> Not Overridable Administrator Settings. Double-click the "Configure clipboard redirection" setting.

Click the radio button next to "Disabled". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Agent'
  tag check_id: 'C-50299r768559_chk'
  tag severity: 'medium'
  tag gid: 'V-246867'
  tag rid: 'SV-246867r768561_rule'
  tag stig_id: 'HRZA-7X-000008'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50253r768560_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
