control 'SV-258927' do
  title 'The vCenter Server must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity.

Synchronizing internal information system clocks to an authoritative time server provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Open the Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

Log in with local operating system administrative credentials or with a Single Sign-On (SSO) account that is a member of the "SystemConfiguration.BashShellAdministrator" group.

Select "Time" on the left navigation pane.

On the resulting pane on the right, verify at least one authorized time server is configured and is listed as "Reachable".

If "NTP" is not enabled and at least one authorized time server configured, this is a finding.'
  desc 'fix', 'Open the VAMI by navigating to https://<vCenter server>:5480.

Log in with local operating system administrative credentials or with an SSO account that is a member of the "SystemConfiguration.BashShellAdministrator" group.

Select "Time" on the left navigation pane.

On the resulting pane on the right, click "Edit" under "Time Synchronization".

Select "NTP" for "Mode" and enter a list of authorized time servers separated by commas. Click "Save".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 vCenter'
  tag check_id: 'C-62667r934437_chk'
  tag severity: 'medium'
  tag gid: 'V-258927'
  tag rid: 'SV-258927r934439_rule'
  tag stig_id: 'VCSA-80-000158'
  tag gtitle: 'SRG-APP-000371'
  tag fix_id: 'F-62576r934438_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
