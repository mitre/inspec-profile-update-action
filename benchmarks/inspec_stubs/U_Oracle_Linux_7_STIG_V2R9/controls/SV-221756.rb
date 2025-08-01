control 'SV-221756' do
  title 'The Oracle Linux operating system must use a separate file system for the system audit data path large enough to hold at least one week of audit data.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Determine if the operating system is configured to have the "/var/log/audit" path is on a separate file system.

# grep /var/log/audit /etc/fstab

If no result is returned, or the operating system is not configured to have "/var/log/audit" on a separate file system, this is a finding.

Verify that "/var/log/audit" is mounted on a separate file system:

# mount | grep "/var/log/audit"

If no result is returned, or "/var/log/audit" is not on a separate file system, this is a finding.

Verify the size of the audit file system:

# df -h /var/log/audit

If the size is insufficient for a week of audit data, this is a finding.'
  desc 'fix', 'Migrate the system audit data path onto an appropriately sized separate file system to store at least one week of audit records.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23471r419340_chk'
  tag severity: 'low'
  tag gid: 'V-221756'
  tag rid: 'SV-221756r853677_rule'
  tag stig_id: 'OL07-00-021330'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-23460r419341_fix'
  tag 'documentable'
  tag legacy: ['V-99251', 'SV-108355']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
