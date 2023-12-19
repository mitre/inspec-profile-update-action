control 'SV-35206' do
  title "The system's access control program must log each system’s access attempt."
  desc 'If access attempts are not logged, then multiple attempts to log on to the system by an unauthorized user may go undetected.'
  desc 'check', "Normally, tcpd logs to the mail facility in the syslog.conf file (normally located within the /etc directory). Determine if syslog is configured to log events by tcpd.
# find /etc -type f -name syslog.conf
# cat <path>/syslog.conf | tr '\\011' ' ' | tr -s ' ' | sed -e 's/^[ \\t]*//' |grep -v “^#” | egrep “mail.debug|mail.info|mail.\\*”

Look for an entry similar to the following, indicating that mail alerts are being logged:
mail.* /var/log/maillog

If no entries for mail exist, then tcpd is not logging and this is a finding."
  desc 'fix', 'Configure the access restriction program to log every access attempt. Ensure the implementation instructions for TCP_WRAPPERS are followed so logging of system access attempts is logged into the system log files. If an alternate application is used, it must support this function.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-35049r2_chk'
  tag severity: 'medium'
  tag gid: 'V-941'
  tag rid: 'SV-35206r2_rule'
  tag stig_id: 'GEN006600'
  tag gtitle: 'GEN006600'
  tag fix_id: 'F-32112r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
