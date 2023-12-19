control 'SV-35058' do
  title 'The SMTP service log file must have mode 0644 or less permissive.'
  desc 'If the SMTP service log file is more permissive than 0644, unauthorized users may be allowed to change the log file.'
  desc 'check', %q(Check the mode of the SMTP service log file.
# cat /etc/syslog.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[  \t]*//'  | grep -v "^#" | egrep -i "mail.info|mail.debug|mail.\*|\*.info|\*.debug|\*.\*" | cut -f 2,2 -d " " | uniq | xargs -n1 ls -lL

Check the configuration to determine which log files contain logs for mail.
# ls -lL <sendmail log file>

If any Sendmail log file permissions are greater than 0644, this is a finding.)
  desc 'fix', 'Change the mode of the SMTP service log file.
# chmod 0644 <sendmail log file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36567r1_chk'
  tag severity: 'medium'
  tag gid: 'V-838'
  tag rid: 'SV-35058r1_rule'
  tag stig_id: 'GEN004500'
  tag gtitle: 'GEN004500'
  tag fix_id: 'F-31935r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
