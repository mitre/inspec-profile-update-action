control 'SV-216034' do
  title 'The operating system must protect against an individual falsely denying having performed a particular action. In order to do so the system must be configured to send audit records to a remote audit server.'
  desc 'Keeping audit records on a remote system reduces the likelihood of audit records being changed or corrupted. Duplicating and protecting the audit trail on a separate system reduces the likelihood of an individual being able to deny performing an action.

Solaris has supported rsyslog since version 11.1 and the differences between syslog and rsyslog are numerous. Solaris 11.4 installs rsyslog by default, but previous versions require a manual installation. When establishing a rsyslog server to forward to, it is important to consider the network requirements for this action.  Note the following configuration options:
There are three ways to forward message: the traditional UDP transport, which is extremely lossy but standard; the plain TCP based transport, which loses messages only during certain situations but is widely available; and the RELP transport, which does not lose messages but is currently available only as part of the rsyslogd 3.15.0 and above.
Examples of each configuration:
UDP  *.* @remotesystemname
TCP  *.* @@remotesystemname
RELP  *.* :omrelp:remotesystemname:2514
Please note that a port number was given as there is no standard port for RELP.'
  desc 'check', 'Audit Configuration rights profile is required.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Check that the syslog audit plugin is enabled.

# pfexec auditconfig -getplugin | grep audit_syslog

If "inactive" appears, this is a finding.

Determine which system-log service instance is online.

# pfexec svcs system-log

Check that the /etc/syslog.conf or /etc/rsyslog.conf file is configured properly:

# grep audit.notice /etc/syslog.conf
or
# grep @@ /etc/rsyslog.conf

If 
audit.notice @remotesystemname , audit.notice !remotesystemname (syslog configuration)
or
*.* @@remotesystemname (rsyslog configuration)
points to an invalid remote system or is commented out, this is a finding.

If no output is produced, this is a finding.

Check the remote syslog host to ensure that audit records can be found for this host.'
  desc 'fix', 'Service Management, Audit Configuration and Audit Control rights profile is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Configure Solaris 11 to use the syslog audit plugin

# pfexec auditconfig -setplugin audit_syslog active 

Determine which system-log service instance is online.

# pfexec svcs system-log

If the default system-log service is online:

# pfedit /etc/syslog.conf 

Add the line:

audit.notice @[remotesystemname]
or
audit.notice ![remotesystemname]

Replacing the remote system name with the correct hostname.

If the rsyslog service is online, modify the /etc/rsyslog.conf file.

# pfedit /etc/rsyslog.conf

Add the line:

*.* @@[remotesystemname]
Or 
*.* :omrelp:[remotesystemname]:[designatedportnumber]

Replacing the remote system name with the correct hostname.

Create the log file on the remote system

# touch /var/adm/auditlog

Refresh the syslog service

# pfexec svcadm refresh system/system-log:default

or

# pfexec svcadm refresh system/system-log:rsyslog

Refresh the audit service

# pfexec audit -s'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17272r462475_chk'
  tag severity: 'low'
  tag gid: 'V-216034'
  tag rid: 'SV-216034r603268_rule'
  tag stig_id: 'SOL-11.1-010350'
  tag gtitle: 'SRG-OS-000061'
  tag fix_id: 'F-17270r462476_fix'
  tag 'documentable'
  tag legacy: ['SV-60703', 'V-47827']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
