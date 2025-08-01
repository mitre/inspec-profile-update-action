control 'SV-234196' do
  title 'The FortiGate device must support organizational requirements to conduct backups of information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner.'
  desc 'Information system backup is a critical step in maintaining data assurance and availability. Information system and security-related documentation contains information pertaining to system configuration and security settings. If this information was not backed up, and a system failure occurred, the security settings would be difficult to reconfigure quickly and accurately. Maintaining a backup of information system and security-related documentation provides for a quicker recovery time when system outages occur.

This control requires the network device to support the organizational central backup process for user account information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click the admin menu available on the upper right-hand corner of the screen.
2. Click Configuration.
3. Click Revisions.
4. Verify at least one saved backed-up occurred within the last week.

If a backup of system configuration was not performed within the last week, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
# config system global
#   set revision-backup-on-logout enable
# end
3. Integrate FortiGate with FortiManager or the organization’s central backup server using SSH to pull saved backups.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37381r611775_chk'
  tag severity: 'medium'
  tag gid: 'V-234196'
  tag rid: 'SV-234196r611777_rule'
  tag stig_id: 'FGFW-ND-000185'
  tag gtitle: 'SRG-APP-000516-NDM-000341'
  tag fix_id: 'F-37346r611776_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000539']
  tag nist: ['CM-6 b', 'CP-9 (c)']
end
