control 'SV-37948' do
  title 'The system must be configured to send audit/system records to a remote audit server.'
  desc "System/Audit records contain evidence that can be used in the investigation of compromised systems. To prevent this evidence from compromise, it must be sent to a separate system continuously. Methods for sending audit records include, but are not limited to, system audit tools used to send logs directly to another host or through the system's syslog service to another host."
  desc 'check', 'Verify the system is configured to forward all audit records to a remote server. If the system is not configured to provide this function, this is a finding.

Procedure:
Ensure the audit option for the kernel is enabled.

# grep "audit" /boot/grub/grub.conf | grep -v "^#"

If the kernel does not have the "audit=1" option specified, this is a finding.

Ensure the kernel auditing is active.

# grep "active" /etc/audisp/plugins.d/syslog.conf | grep -v "^#"

If the "active" setting is either missing or not set to "yes", this is a finding.

Ensure all audit records are forwarded to a remote server.

# grep "\\*.\\*" /etc/syslog.conf |grep "@" | grep -v "^#" (for syslog)
or:
# grep "\\*.\\*" /etc/rsyslog.conf | grep "@" | grep -v "^#" (for rsyslog)

If neither of these lines exist, it is a finding.'
  desc 'fix', 'Configure the system to send audit records to a remote server. 

Procedure:
These instructions assume a known remote audit server is available to this system. 
Modify /etc/syslog.conf or /etc/rsyslog.conf to contain a line sending all audit records to a remote audit server. The server is specified by placing an "@" before the DNS name or IP address in the line. 

*.* @<remote audit server>

Edit the "active" line in /etc/audisp/plugins.d/syslog.conf so it shows "active = yes".

Restart audit and syslog:
# service auditd restart
# service syslog restart 
Or:
# service rsyslog restart'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37233r6_chk'
  tag severity: 'low'
  tag gid: 'V-24357'
  tag rid: 'SV-37948r4_rule'
  tag stig_id: 'GEN002870'
  tag gtitle: 'GEN002870'
  tag fix_id: 'F-32440r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000136']
  tag nist: ['AU-3 (2)']
end
