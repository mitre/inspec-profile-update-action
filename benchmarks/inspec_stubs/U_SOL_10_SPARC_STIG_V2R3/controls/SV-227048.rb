control 'SV-227048' do
  title "The system's access control program must log each system access attempt."
  desc 'If access attempts are not logged, then multiple attempts to log on to the system by an unauthorized user may go undetected.'
  desc 'check', 'Normally, TCPD logs to the mail facility in /etc/syslog.conf.  Determine if syslog is configured to log events by TCPD.

Procedure:
# more /etc/syslog.conf

Look for entries similar to the following:
mail.debug				/var/adm/maillog
mail.none					/var/adm/maillog
mail.*					/var/log/mail
auth.info					/var/log/messages

The above entries would indicate mail alerts are being logged.  If no entries for mail exist, then TCPD is not logging and this is a finding.'
  desc 'fix', 'Configure the access restriction program to log every access attempt.  Ensure the implementation instructions for TCP_WRAPPERS are followed, so system access attempts are logged into the system log files.  If an alternate application is used, it must support this function.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36420r602863_chk'
  tag severity: 'medium'
  tag gid: 'V-227048'
  tag rid: 'SV-227048r603265_rule'
  tag stig_id: 'GEN006600'
  tag gtitle: 'SRG-OS-000470'
  tag fix_id: 'F-36384r602864_fix'
  tag 'documentable'
  tag legacy: ['SV-941', 'V-941']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
