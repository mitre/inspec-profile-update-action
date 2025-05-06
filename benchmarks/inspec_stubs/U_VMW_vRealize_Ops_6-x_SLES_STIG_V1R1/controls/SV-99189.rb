control 'SV-99189' do
  title 'The system syslog service must log informational and more severe SMTP service messages.'
  desc 'If informational and more severe SMTP service messages are not logged, malicious activity on the system may go unnoticed.'
  desc 'check', 'Check the "/etc/syslog-ng/syslog-ng.conf" file for the following log entries:

filter f_mailinfo { level(info) and facility(mail); };
filter f_mailwarn { level(warn) and facility(mail); };
filter f_mailerr { level(err, crit) and facility(mail); };
filter f_mail { facility(mail); };

If any of the above log entries are present, this is not a finding.'
  desc 'fix', 'Edit the "/etc/syslog-ng/syslog-ng.conf" file and add the following log entries:

filter f_mailinfo { level(info) and facility(mail); };
filter f_mailwarn { level(warn) and facility(mail); };
filter f_mailerr { level(err, crit) and facility(mail); };
filter f_mail { facility(mail); };

destination mailinfo { file("/var/log/mail.info"); };
log { source(src); filter(f_mailinfo); destination(mailinfo); };

destination mailwarn { file("/var/log/mail.warn"); };
log { source(src); filter(f_mailwarn); destination(mailwarn); };

destination mailerr { file("/var/log/mail.err" fsync(yes)); };
log { source(src); filter(f_mailerr); destination(mailerr); };'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88231r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88539'
  tag rid: 'SV-99189r1_rule'
  tag stig_id: 'VROM-SL-000575'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95281r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
