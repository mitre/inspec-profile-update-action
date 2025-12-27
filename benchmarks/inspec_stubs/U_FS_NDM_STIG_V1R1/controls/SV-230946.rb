control 'SV-230946' do
  title 'Forescout must prohibit installation of software without explicit privileged permission by only authorized individuals.'
  desc 'Allowing anyone to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system.  This requirement applies to code changes and upgrades for all network devices.'
  desc 'check', 'Determine if the network device prohibits installation of software without explicit privileged status.  This requirement may be verified by demonstration or configuration review.

1. From the menu, select Tools >> Options >> User Console and Options.
2. Select (highlight) the user profile to be reviewed (group or user) and then select Edit >> Permissions.
3. Check a sampling of users against the current SSP to verify only the users that should have privilege to update software have the Software Upgrade privilege selected.

If installation of software is not prohibited without explicit privileged status, this is a finding.'
  desc 'fix', 'Remove accounts that are not authorized. Do not remove the account of last resort. 

Compare users with the current SSP and ensure only the users that should have the privilege to update software have the Software Upgrade privilege selected.

1. From the menu, select Tools >> Options >> User Console and Options.
2. Select (highlight) the user profile to be reviewed (group or user) and then select Edit >> Permissions.
3. Disable or delete unauthorized users.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33876r603677_chk'
  tag severity: 'medium'
  tag gid: 'V-230946'
  tag rid: 'SV-230946r615886_rule'
  tag stig_id: 'FORE-NM-000190'
  tag gtitle: 'SRG-APP-000378-NDM-000302'
  tag fix_id: 'F-33849r603678_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
