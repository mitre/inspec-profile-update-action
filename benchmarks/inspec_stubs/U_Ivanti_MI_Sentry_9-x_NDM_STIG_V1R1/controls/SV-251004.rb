control 'SV-251004' do
  title 'MobileIron Sentry must be configured to conduct backups of system level information contained in the information system when changes occur.'
  desc 'This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Identify/validate MobileIron Sentry support for periodic backups. 

This is done via the virtual machine.

Check with the virtual team to verify backups are scheduled.

If the backups are not scheduled, this is a finding.'
  desc 'fix', 'Ensure the virtual solution provides periodic backups. 
 
Refer to "MobileIron Sentry Installation Guide", section "Periodic backups for VMware", pages 6-7.'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54439r802232_chk'
  tag severity: 'low'
  tag gid: 'V-251004'
  tag rid: 'SV-251004r802234_rule'
  tag stig_id: 'MOIS-ND-000950'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-54393r802233_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
