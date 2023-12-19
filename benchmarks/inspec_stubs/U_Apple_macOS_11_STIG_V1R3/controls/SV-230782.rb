control 'SV-230782' do
  title 'The macOS system must provide an immediate warning to the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.'
  desc 'The audit service must be configured to require a minimum percentage of free disk space in order to run. This ensures that audit will notify the administrator that action is required to free up more disk space for audit logs.

When "minfree" is set to 25 percent, security personnel are notified immediately when the storage volume is 75 percent full and are able to plan for audit record storage capacity expansion.'
  desc 'check', 'The check displays the "% free" to leave available for the system. The audit system will not write logs if the volume has less than this percentage of free disk space. To view the current setting, run the following command:

/usr/bin/sudo /usr/bin/grep ^minfree /etc/security/audit_control

If this returns no results, or does not contain "25", this is a finding.'
  desc 'fix', %q(Edit the "/etc/security/audit_control" file and change the value for "minfree" to "25" using the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

A text editor may also be used to implement the required updates to the "/etc/security/audit_control file".)
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33727r607233_chk'
  tag severity: 'medium'
  tag gid: 'V-230782'
  tag rid: 'SV-230782r599842_rule'
  tag stig_id: 'APPL-11-001030'
  tag gtitle: 'SRG-OS-000343-GPOS-00134'
  tag fix_id: 'F-33700r607597_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
