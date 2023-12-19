control 'SV-246873' do
  title 'The Horizon Agent desktops must not allow client drive redirection.'
  desc 'Data loss prevention is a primary concern for the DoD, maintaining positive control of data at all times and only allowing flows over channels that are for that explicit purpose and monitored appropriately. By default, the Horizon Client, Agent, and guest operating systems will coordinate to allow drives local to the client to be redirected over the Client connection and mounted in the virtual desktop. This configuration must be modified to disallow drive sharing in order to protect sensitive DoD data from being maliciously, accidentally, or casually removed from the controlled environment.'
  desc 'check', 'Ensure the vdm_rdsh_server.admx template is added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Device and Resource Redirection. Double-click the "Do not allow drive redirection" setting.

If "Do not allow drive redirection" is not "Enabled", this is a finding.'
  desc 'fix', 'Ensure the vdm_rdsh_server.admx template is added. Open the "Group Policy Management" MMC snap-in. Open the site-specific GPO applying Horizon settings to the VDI desktops or RDS hosts.

Navigate to Computer Configuration >> Policies >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Device and Resource Redirection. Double-click the "Do not allow drive redirection" setting.

Click the radio button next to "Enabled". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware Horizon 7.13 Agent'
  tag check_id: 'C-50305r768577_chk'
  tag severity: 'medium'
  tag gid: 'V-246873'
  tag rid: 'SV-246873r768579_rule'
  tag stig_id: 'HRZA-7X-000014'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-50259r768578_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
