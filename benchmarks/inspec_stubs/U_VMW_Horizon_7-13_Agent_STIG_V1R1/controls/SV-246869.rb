control 'SV-246869' do
  title 'The Horizon Agent must not allow drag and drop for Blast.'
  desc 'Data loss prevention is a primary concern for the DoD, maintaining positive control of data at all times and only allowing flows over channels that are for that explicit purpose and monitored appropriately. Additionally, data coming into the environment must be through allowed channels and inspected appropriately. By default, the Blast protocol on the Horizon Agent will allow drag and drop actions from the client to the desktop. This must be configured to disabled in both directions.'
  desc 'check', 'Ensure the vdm_blast.admx template is added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Blast. Double-click the "Configure drag and drop direction" setting.

If "Configure drag and drop direction" is not "Enabled", this is a finding.

In the drop-down under "Configure drag and drop", if "Disabled in both directions" is not selected, this is a finding.'
  desc 'fix', 'Ensure the vdm_blast.admx template is added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> VMware Blast. Double-click the "Configure drag and drop" setting.

Click the radio button next to "Enabled".

In the drop-down under "Configure drag and drop", select "Disabled in both directions". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Agent'
  tag check_id: 'C-50301r768565_chk'
  tag severity: 'medium'
  tag gid: 'V-246869'
  tag rid: 'SV-246869r768567_rule'
  tag stig_id: 'HRZA-7X-000010'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50255r768566_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
