control 'SV-257180' do
  title 'The macOS system must provide an immediate warning to the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.'
  desc 'The audit service must be configured to require a minimum percentage of free disk space to run. This ensures that audit will notify the administrator that action is required to free up more disk space for audit logs.

When "minfree" is set to 25 percent, security personnel are notified immediately when the storage volume is 75 percent full and are able to plan for audit record storage capacity expansion.'
  desc 'check', 'Verify the macOS system is configured to require a minimum of 25 percent free disk space for audit record storage with the following command:

/usr/bin/sudo /usr/bin/grep ^minfree /etc/security/audit_control

minfree:25

If "minfree" is not set to "25", this is a finding.'
  desc 'fix', %q(Configure the macOS system to require 25 percent free disk space for audit record storage with the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

Alternatively, use a text editor to update the "/etc/security/audit_control" file.)
  impact 0.3
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60865r905171_chk'
  tag severity: 'low'
  tag gid: 'V-257180'
  tag rid: 'SV-257180r905173_rule'
  tag stig_id: 'APPL-13-001030'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-60806r905172_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
