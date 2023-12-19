control 'SV-45564' do
  title 'The system must be configured to send audit records to a remote audit server.'
  desc "Audit records contain evidence that can be used in the investigation of compromised systems. To prevent this evidence from compromise, it must be sent to a separate system continuously. Methods for sending audit records include, but are not limited to, system audit tools used to send logs directly to another host or through the system's syslog service to another host."
  desc 'check', %q(Verify the system is configured to forward all audit records to a remote server. If the system is not configured to provide this function, this is a finding.

Procedure:
Ensure the audit option for the kernel is enabled.

# cat /proc/cmdline | tr ' ' '\n' | grep -i audit

If the kernel does not have the "audit=1" option specified, this is a finding.

Ensure the kernel auditing is active.

# /sbin/auditctl -s | tr ' ' '\n' | egrep 'enabled|pid'
When auditing is active, the “enabled” value is set to 1 and the “pid” value will be greater than 0.
If the "enabled" setting is either missing or not set to "1", this is a finding.
If the “pid” setting is 0, the audit daemon is not running and this is also a finding.

Ensure the syslog plugin is active for the audit dispatch daemon.


# grep "active" /etc/audisp/plugins.d/syslog.conf | grep -v "^#"

If the "active" setting is either missing or not set to "yes", this is a finding.

Ensure all audit records are fowarded to a remote server.

# grep "\*.\*" /etc/syslog.conf |grep "@" | grep -v "^#" (for syslog)
or:
# grep "\*.\*" /etc/rsyslog.conf | grep "@" | grep -v "^#" (for rsyslog)


If neither of these lines exist, it is a finding.)
  desc 'fix', 'Configure the system to send audit records to a remote server. 

Procedure:
These instructions assume a known remote audit server is available to this system.

 Add ‘audit=1’ to parameters line for the active kernel in the /etc/zipl.conf file.
OR 
Add ‘audit=1’ as a line in the file referenced by the parmfile option for the active kernel in the /etc/zipl.conf file.
An update to the boot configuration parameters requires a system restart to activate the change.
Edit the "active" line in /etc/audisp/plugins.d/syslog.conf so it shows "active = yes".

Modify /etc/rsyslog.conf to contain a line sending all audit records to a remote audit server. The server is specified by placing an "@" before the DNS name or IP address in the line. 

*.* @<remote audit server>


Restart audit and syslog:
# rcauditd restart
# rcsyslog restart
        OR
# service auditd restart
# service syslog restart'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42914r3_chk'
  tag severity: 'low'
  tag gid: 'V-24357'
  tag rid: 'SV-45564r2_rule'
  tag stig_id: 'GEN002870'
  tag gtitle: 'GEN002870'
  tag fix_id: 'F-38961r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000136']
  tag nist: ['AU-3 (2)']
end
