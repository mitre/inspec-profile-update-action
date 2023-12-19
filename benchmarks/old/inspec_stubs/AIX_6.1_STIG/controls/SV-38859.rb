control 'SV-38859' do
  title 'The system must be configured to send audit records to a remote audit server.'
  desc "Audit records contain evidence that can be used in the investigation of compromised systems. To prevent this evidence from compromise, it must be sent to a separate system continuously. Methods for sending audit records include, but are not limited to, system audit tools used to send logs directly to another host or through the system's syslog service to another host."
  desc 'check', 'Ask the SA to provide information on the remote logging of audit records.  Verify the configuration described is functioning.  If no method of remote logging of audit records is in place or functioning, this is a finding.

Methods of remote audit record logging will be site-specific and may depend on the use of third-party tools.  One possible method with AIX is the use of the audit streams facility such as:

Verify "streammode = on" in /etc/security/audit/config.

Check that /etc/security/audit/streamcmds sends stream logs to the syslog facility with an entry such as:
/usr/sbin/auditstream | auditpr -v | /usr/bin/logger -p local7.info &

Check that the /etc/syslog.conf file is configured to send local7.info to a remote server with an entry such as:
local7.info @logserver'
  desc 'fix', 'Configure the system to send audit records to a remote system.  The actual method is left to site discretion and may involve the use of third-party products.

One method for performing remote audit logging involves streaming audit records to syslog and using syslog to send the records to another system. 
  
Enable stream mode by editing the /etc/security/audit/config and set streammode = on.

Edit  /etc/security/audit/streamcmds to send stream logs to the syslog facility with an entry such as:
/usr/sbin/auditstream | auditpr -v | /usr/bin/logger -p local7.info &

Edit the /etc/syslog.conf file to configure syslog to send local7.info to a remote server with an entry such as:
Local7.info @logserver'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37851r2_chk'
  tag severity: 'low'
  tag gid: 'V-24357'
  tag rid: 'SV-38859r1_rule'
  tag stig_id: 'GEN002870'
  tag gtitle: 'GEN002870'
  tag fix_id: 'F-33114r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTB-1'
  tag cci: ['CCI-000136']
  tag nist: ['AU-3 (2)']
end
