control 'SV-218672' do
  title 'The systems access control program must log each system access attempt.'
  desc 'If access attempts are not logged, then multiple attempts to log on to the system by an unauthorized user may go undetected.'
  desc 'check', 'The tcp_wrappers package is provided with the RHEL distribution. Other access control programs may be available but will need to be checked manually. Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.

Normally, tcpd logs to the mail facility in "/etc/syslog.conf" or "/etc/rsyslog.conf". Determine if syslog or rsyslog is configured to log events by tcpd.

Procedure:

# more /etc/syslog.conf

Or:

# more /etc/rsyslog.conf

Look for entries similar to the following:

mail.debug /var/adm/maillog
mail.none /var/adm/maillog
mail.* /var/log/mail
authpriv.info /var/log/messages

The above entries would indicate mail alerts are being logged.

If no entries for mail exist, then tcpd is not logging this is a finding.

If an alternate access control program is used and it does not provide logging of access attempts, this is a finding.'
  desc 'fix', 'Configure the access restriction program to log every access attempt. Ensure the implementation instructions for tcp_wrappers are followed so system access attempts are recorded to the system log files. If an alternate application is used, it must support this function.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20147r556430_chk'
  tag severity: 'medium'
  tag gid: 'V-218672'
  tag rid: 'SV-218672r603259_rule'
  tag stig_id: 'GEN006600'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-20145r556431_fix'
  tag 'documentable'
  tag legacy: ['V-941', 'SV-63571']
  tag cci: ['CCI-000366', 'CCI-000126']
  tag nist: ['CM-6 b', 'AU-2 c']
end
