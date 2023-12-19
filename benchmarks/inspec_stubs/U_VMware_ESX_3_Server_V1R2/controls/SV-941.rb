control 'SV-941' do
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
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-888r2_chk'
  tag severity: 'medium'
  tag gid: 'V-941'
  tag rid: 'SV-941r2_rule'
  tag stig_id: 'GEN006600'
  tag gtitle: 'GEN006600'
  tag fix_id: 'F-1095r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
