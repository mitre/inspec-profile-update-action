control 'SV-227737' do
  title 'The system must be configured to send audit records to a remote audit server.'
  desc "Audit records contain evidence that can be used in the investigation of compromised systems.  To prevent this evidence from compromise, it must be sent to a separate system continuously. Methods for sending audit records include, but are not limited to, system audit tools used to send logs directly to another host or through the system's syslog service to another host."
  desc 'check', %q(Audit records may be sent to a remote server in two ways, via an NFS mount of the audit directory, or via the audit_syslog plugin (if available).

NFS:
Check the "dir" parameter in /etc/security/audit_control.  If the directory is on an NFS mount to a remote server, there is no finding.

SYSLOG:
Check the "plugin" parameter in /etc/security/audit_control.  Confirm that the audit_syslog.so* plugin is listed with "p_flags=all".
# grep audit_syslog.so /etc/security/audit_control
Check that syslogd is sending messages to a remote server (GEN005450):
# grep '@' /etc/syslog.conf | grep -v '^#'
If both auditd is configured to send audit records to syslog, and syslogd is configured to send messages to a remote server, there is no finding.

If auditd is saving audit records on a local directory, and audit records are not being sent to a remote server via syslog, this is a finding.)
  desc 'fix', 'Update the /etc/security/audit_control file to save audit records to a remote NFS mount.

dir:<remote NFS directory>

OR

If the /usr/lib/security/audit_syslog.so* exists, update the /etc/security/audit_control file to send all audit records to syslog and update /etc/syslog.conf to send all audit messages to a remote server.

/etc/security/audit_control:
plugin:name=audit_syslog.so.1; p_flags=all

/etc/syslog.conf:
audit.* @<remote syslog server>'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36463r602992_chk'
  tag severity: 'low'
  tag gid: 'V-227737'
  tag rid: 'SV-227737r603266_rule'
  tag stig_id: 'GEN002870'
  tag gtitle: 'SRG-OS-000215'
  tag fix_id: 'F-36427r602993_fix'
  tag 'documentable'
  tag legacy: ['V-24357', 'SV-39881']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
