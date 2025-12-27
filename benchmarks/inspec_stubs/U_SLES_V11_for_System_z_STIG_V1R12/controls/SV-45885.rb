control 'SV-45885' do
  title 'The FTP daemon must be configured for logging or verbose mode.'
  desc 'The -l option allows basic logging of connections.  The verbose (on HP) and the debug (on Solaris) allow logging of what files the ftp session transferred.  This extra logging makes it possible to easily track which files are being transferred onto or from a system.  If they are not configured, the only option for tracking is the audit files.  The audit files are much harder to read.  If auditing is not properly configured, then there would be no record at all of the file transfer transactions.'
  desc 'check', 'Find if logging is applied to the ftp daemon. The procedure depends on the implementation of ftpd used by the system. 

Procedures:

For vsftpd: 
If vsftpd is started by xinetd:

#grep vsftpd /etc/xinetd.d/*
This will indicate the xinetd.d startup file

#grep server_args <vsftpd xinetd.d startup file>
This will indicate the vsftpd config file used when starting through xinetd. 
If the line is missing then "/etc/vsftpd.conf", the default config file, is used.

#grep xferlog_enable <vsftpd config file>
If "xferlog_enable" is missing or is not set to "yes", this is a finding.

If vsftp is not started by xinetd:
#grep xferlog_enable /etc/vsftpd.conf
If "xferlog_enable" is missing or is not set to "yes", this is a finding.


For gssftp:
Find if the -l option will be applied when xinetd starts gssftp
# grep server-args /etc/xinetd.d/gssftp
If the line is missing or does not contain at least one -l, this is a finding.'
  desc 'fix', 'Enable logging by changing ftpd startup or config files.

Procedure:
The procedure depends on the implementation of ftpd used by the system. 

For vsftpd: 

Ensure the server settings in "/etc/vsftpd.conf" (or other configuration file specified by the vaftpd xinetd.d startup file) contains:

xferlog_enable = yes

For gssftp:
If the "disable" server setting is missing or set to "no" in "/etc/xinetd.d/gssftp" then
ensure the server settings in "/etc/xinetd.d/gssftp" contains:

server_args = -l 

The -l option may be added up to three times. Each -l will provide increasing verbosity on the log. Refer to the main page for ftpd for more information.

For both if started using xinetd:
If the "disable" server setting is missing or set to "no" in the /etc/xinetd.d startup file then
ensure the server settings contains:

log_on_success += DURATION USERID
This will log the startup and shutdown of the daemon.

log_on_failure += HOST USERID'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43202r1_chk'
  tag severity: 'low'
  tag gid: 'V-845'
  tag rid: 'SV-45885r1_rule'
  tag stig_id: 'GEN004980'
  tag gtitle: 'GEN004980'
  tag fix_id: 'F-39263r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
