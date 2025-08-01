control 'SV-204506' do
  title 'The Red Hat Enterprise Linux operating system must be configured to off-load audit logs onto a different system or storage media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

One method of off-loading audit logs in Red Hat Enterprise Linux is with the use of the audisp-remote dameon.  Without the configuration of the "au-remote" plugin, the audisp-remote daemon will not off load the logs from the system being audited.

'
  desc 'check', 'Verify the "au-remote" plugin is configured to always off-load audit logs using the audisp-remote daemon:

# cat /etc/audisp/plugins.d/au-remote.conf | grep -v "^#"

active = yes
direction = out
path = /sbin/audisp-remote
type = always
format = string

If "active" is not set to "yes", "direction" is not set to "out", "path" is not set to "/sbin/audisp-remote", "type" is not set to "always", or any of the lines are commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or storage media.

If there is no evidence that the system is configured to off-load audit logs to a different system or storage media, this is a finding.'
  desc 'fix', 'Edit the /etc/audisp/plugins.d/au-remote.conf file and add or update the following values:

active = yes
direction = out
path = /sbin/audisp-remote
type = always

The audit daemon must be restarted for changes to take effect:

# service auditd restart'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4630r462469_chk'
  tag severity: 'medium'
  tag gid: 'V-204506'
  tag rid: 'SV-204506r861009_rule'
  tag stig_id: 'RHEL-07-030201'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-4630r858479_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag legacy: ['SV-95729', 'V-81017']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
