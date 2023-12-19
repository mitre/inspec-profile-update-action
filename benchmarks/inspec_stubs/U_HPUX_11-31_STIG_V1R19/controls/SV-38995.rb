control 'SV-38995' do
  title 'The FTP daemon must be configured for logging or verbose mode.'
  desc 'The -l option allows basic logging of connections.  The verbose (on HP) and the debug (on Solaris) allow logging of what files the ftp session transferred.  This extra logging makes it possible to easily track which files are being transferred onto or from a system.  If they are not configured, the only option for tracking is the audit files.  The audit files are much harder to read.  If auditing is not properly configured, then there would be no record at all of the file transfer transactions.'
  desc 'check', 'Perform:

# grep ftpd /etc/inetd.conf

Check the line for ftpd to see if the -v options are invoked. If not,  this is a finding.'
  desc 'fix', 'The v option enables more verbose logging, shows the accessed file names, and the logout timestamp. The syslog.conf file must be configured to log daemon.info and daemon.debug to a proper log file in which to capture the data.

The output goes into the system log file. The log file is /var/adm/syslog.  

Edit the inetd.conf file.
Locate the line that defines ftpd by typing /ftpd/cr.
Add the v option where ftpd appears to the right of the pathname for ftpd. For instance:

ftp stream tcp nowait root /usr/sbin/in.ftpd in.ftpd -v

This is a requirement even when the system is using TCP_WRAPPERS and/or secure shell. The only time it is not a requirement is if the ftp daemon is not configured to run.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-37978r2_chk'
  tag severity: 'low'
  tag gid: 'V-845'
  tag rid: 'SV-38995r1_rule'
  tag stig_id: 'GEN004980'
  tag gtitle: 'GEN004980'
  tag fix_id: 'F-33221r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
