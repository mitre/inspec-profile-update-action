control 'SV-234195' do
  title 'The FortiGate device must conduct backups of system-level information contained in the information system when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click the admin menu available on the upper right-hand corner of the screen.
2. Click Configuration.
3. Click Revisions.
4. Verify a list of saved backed-up configurations are available.

If saved backups of system configuration do not exist, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
# config system global
#   set revision-backup-on-logout enable
# end
3. Integrate FortiGate with FortiManager or the organization’s central backup server using SSH to pull saved backups. 

Note: All backups performed by super admin contain global setting and settings for any VDOMs.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37380r611772_chk'
  tag severity: 'medium'
  tag gid: 'V-234195'
  tag rid: 'SV-234195r611774_rule'
  tag stig_id: 'FGFW-ND-000180'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-37345r611773_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
