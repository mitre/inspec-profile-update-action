control 'SV-37757' do
  title "The system's access control program must log each system access attempt."
  desc 'If access attempts are not logged, then multiple attempts to log on to the system by an unauthorized user may go undetected.'
  desc 'check', 'The tcp_wrappers package is provided with the RHEL distribution. Other access control programs may be available but will need to be checked manually. Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.

Normally, tcpd logs to the mail facility in "/etc/syslog.conf" or “/etc/rsyslog.conf”. Determine if syslog or rsyslog is configured to log events by tcpd.

Procedure:

# grep -E “(\\*.info|\\*.debug|authpriv.info|authpriv.debug|authpriv.\\*)” /etc/syslog.conf | grep –v ‘#’

Or:

# grep -E “(\\*.info|\\*.debug|authpriv.info|authpriv.debug|authpriv.\\*)” /etc/rsyslog.conf | grep –v ‘#’

If no entries exist, this is a finding.
If there are no “authpriv.info”, “authpriv.debug”, “authpriv.*” or “*.info” or “*.debug” not followed by “authpriv.none”, this is a finding.


If an alternate access control program is used and it does not provide logging of access attempts, this is a finding.'
  desc 'fix', 'Configure the access restriction program to log every access attempt. Ensure the implementation instructions for tcp_wrappers are followed so system access attempts are recorded to the system log files. If an alternate application is used, it must support this function.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36954r3_chk'
  tag severity: 'medium'
  tag gid: 'V-941'
  tag rid: 'SV-37757r3_rule'
  tag stig_id: 'GEN006600'
  tag gtitle: 'GEN006600'
  tag fix_id: 'F-32219r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
