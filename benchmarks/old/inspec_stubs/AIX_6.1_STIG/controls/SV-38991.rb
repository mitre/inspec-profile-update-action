control 'SV-38991' do
  title 'The FTP daemon must be configured for logging or verbose mode.'
  desc 'The -l option allows logging of connections.  This extra logging makes it possible to easily track which files are being transferred onto or from a system.  If they are not configured, the only option for tracking is the audit files.  The audit files are much harder to read.  If auditing is not properly configured, then there would be no record at all of the file transfer transactions.'
  desc 'check', 'Perform:

# grep ftpd /etc/inetd.conf, 

Check the line for ftpd to check if the -l argument.  If the ftpd is invoked without the -l argument,  this is a finding.

Check the /etc/syslog.conf file for daemon.info  or *.info.     
# more /etc/syslog.conf
If daemon.info or *.info is not being logged,  this is a finding.'
  desc 'fix', 'Edit the /etc/inetd.conf file and add the -l argument to the ftpd service line.

# vi /etc/inetd.conf

Restart inetd.conf

# refresh -s inetd

Add daemon.info or *.info to the /etc/syslog.conf file.

#vi /etc/syslog.conf
*.info /var/log/syslog

Restart the syslog daemon.

# refresh -s syslogd'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37953r1_chk'
  tag severity: 'low'
  tag gid: 'V-845'
  tag rid: 'SV-38991r1_rule'
  tag stig_id: 'GEN004980'
  tag gtitle: 'GEN004980'
  tag fix_id: 'F-33206r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
