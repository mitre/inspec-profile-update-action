control 'SV-219956' do
  title 'AIX must be configured so that the audit system takes appropriate action when the audit storage volume is full.'
  desc 'Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records.'
  desc 'check', 'Verify the action the operating system takes if the disk the audit records are written to becomes full.

Verify that the file "/etc/security/audit/config" includes the required settings with the following command:

# cat /etc/security/audit/config

bin:
trail = /audit/trail
bin1 = /audit/bin1
bin2 = /audit/bin2
binsize = 25000
cmds = /etc/security/audit/bincmds
freespace = 65536
backuppath = /audit
backupsize = 0
bincompact = off

If any of the configurations listed above is missing or not set to the listed value or greater, this is a finding.'
  desc 'fix', 'Edit the /etc/security/audit/config file and add/modify the following values:

Note: The values for "binsize" and "freespace" are the minimum required values. These values can be increased to meet organizationally defined values that exceed the listed values.

bin:
trail = /audit/trail
bin1 = /audit/bin1
bin2 = /audit/bin2
binsize = 25000
cmds = /etc/security/audit/bincmds
freespace = 65536
backuppath = /audit
backupsize = 0
bincompact = off

Restart the audit process:
# /usr/sbin/audit shutdown
# /usr/sbin/audit start'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-21667r364827_chk'
  tag severity: 'medium'
  tag gid: 'V-219956'
  tag rid: 'SV-219956r508663_rule'
  tag stig_id: 'AIX7-00-002017'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-21666r364828_fix'
  tag 'documentable'
  tag legacy: ['SV-109109', 'V-100005']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
