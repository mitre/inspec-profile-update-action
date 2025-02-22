control 'SV-45930' do
  title 'The systems access control program must log each system access attempt.'
  desc 'If access attempts are not logged, then multiple attempts to log on to the system by an unauthorized user may go undetected.'
  desc 'check', 'The tcp_wrappers package (i.e. tcpd) is provided with the SLES mainframe distribution. Other access control programs may be available but will need to be checked manually.

Normally, tcpd logs to the mail facility in "/etc/syslog.conf". Determine if syslog is configured to log events by tcpd.

Procedure:
# more /etc/syslog.conf

Look for entries similar to the following:
mail.debug /var/adm/maillog
mail.none /var/adm/maillog
mail.* /var/log/mail
authpriv.info /var/log/messages

The above entries would indicate mail alerts are being logged. If no entries for mail exist, then tcpd is not logging this is a finding.

If an alternate access control program is used and it does not provide logging of access attempts, this is a finding.'
  desc 'fix', 'Configure the access restriction program to log every access attempt. Ensure the implementation instructions for tcp_wrappers (i.e. tcpd) are followed so system access attempts are recorded to the system log files. If an alternate application is used, it must support this function.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43234r1_chk'
  tag severity: 'medium'
  tag gid: 'V-941'
  tag rid: 'SV-45930r1_rule'
  tag stig_id: 'GEN006600'
  tag gtitle: 'GEN006600'
  tag fix_id: 'F-39306r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
