control 'SV-202137' do
  title 'The network device must support organizational requirements to conduct backups of information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner.'
  desc 'Information system backup is a critical step in maintaining data assurance and availability. Information system and security-related documentation contains information pertaining to system configuration and security settings. If this information were not backed up, and a system failure were to occur, the security settings would be difficult to reconfigure quickly and accurately. Maintaining a backup of information system and security-related documentation provides for a quicker recovery time when system outages occur.

This control requires the network device to support the organizational central backup process for user account information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Review the network device backup configuration to determine if the network device backs up the information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner.

If the network device does not backup the information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner, this is a finding.'
  desc 'fix', 'Configure the network device to conduct backups of information system documentation, including security-related documentation, when changes occur or weekly, whichever is sooner.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2263r382076_chk'
  tag severity: 'medium'
  tag gid: 'V-202137'
  tag rid: 'SV-202137r401224_rule'
  tag stig_id: 'SRG-APP-000516-NDM-000341'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-2264r382077_fix'
  tag 'documentable'
  tag legacy: ['SV-69555', 'V-55309']
  tag cci: ['CCI-000539', 'CCI-000366']
  tag nist: ['CP-9 (c)', 'CM-6 b']
end
