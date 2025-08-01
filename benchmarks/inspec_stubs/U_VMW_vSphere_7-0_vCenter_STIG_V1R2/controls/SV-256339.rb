control 'SV-256339' do
  title 'The vCenter Server must be configured to send logs to a central log server.'
  desc 'vCenter must be configured to send near real-time log data to syslog collectors so information will be available to investigators in the case of a security incident or to assist in troubleshooting.'
  desc 'check', 'Open the Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

Log in with local operating system administrative credentials or with a Single Sign-On (SSO) account that is a member of the "SystemConfiguration.BashShellAdministrator" group.

Select "Syslog" on the left navigation pane.

On the resulting pane on the right, verify at least one site-specific syslog receiver is configured and is listed as "Reachable".

If no valid syslog collector is configured or if the collector is not listed as "Reachable", this is a finding.'
  desc 'fix', 'Open the VAMI by navigating to https://<vCenter server>:5480.

Log in with local operating system administrative credentials or with an SSO account that is a member of the "SystemConfiguration.BashShellAdministrator" group.

Select "Syslog" on the left navigation pane.

On the resulting pane on the right, click "Edit" or "Configure".

Edit or add the address and port of a site-specific syslog aggregator or Security Information Event Management (SIEM) system with the appropriate protocol.

User Datagram Protocol (UDP) is discouraged due to its stateless and unencrypted nature. Transport Layer Security (TLS) is preferred. 

Click "Save".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCenter'
  tag check_id: 'C-60014r885626_chk'
  tag severity: 'medium'
  tag gid: 'V-256339'
  tag rid: 'SV-256339r885628_rule'
  tag stig_id: 'VCSA-70-000148'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-59957r885627_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
