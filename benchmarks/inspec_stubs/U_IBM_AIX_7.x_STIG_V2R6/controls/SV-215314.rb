control 'SV-215314' do
  title 'AIX must be configured to use syslogd to log events by TCPD.'
  desc 'Without auditing the enforcement of access restrictions against changes to the application configuration, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation for after-the-fact actions.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Normally, TCPD logs to the "mail" facility in "/etc/syslog.conf". Determine if syslog is configured to log events by TCPD. 

Procedure: 
# more /etc/syslog.conf 

Look for entries similar to the following: 
mail.debug  /var/adm/maillog 
mail.none  /var/adm/maillog 
mail.*  /var/log/mail 
auth.info  /var/log/messages 

The above entries would indicate mail alerts are being logged. 

If no entries for "mail" exist, then TCPD is not logging and this is a finding.'
  desc 'fix', 'Configure the access restriction program to log every access attempt. Ensure the implementation instructions for TCP_WRAPPERS are followed, so system access attempts are logged into the system log files. If an alternate application is used, it must support this function. Edit the "/etc/syslog.conf" file by writing the following to the file.
auth.info /var/log/messages

# touch /var/log/messages
# refresh -s yslogd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16512r294393_chk'
  tag severity: 'medium'
  tag gid: 'V-215314'
  tag rid: 'SV-215314r508663_rule'
  tag stig_id: 'AIX7-00-002133'
  tag gtitle: 'SRG-OS-000365-GPOS-00152'
  tag fix_id: 'F-16510r294394_fix'
  tag 'documentable'
  tag legacy: ['SV-101631', 'V-91533']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
