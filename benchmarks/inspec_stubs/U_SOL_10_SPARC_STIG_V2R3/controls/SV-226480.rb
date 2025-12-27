control 'SV-226480' do
  title 'The system must log successful and unsuccessful access to the root account.'
  desc 'If successful and unsuccessful logins and logouts are not monitored or recorded, access attempts cannot be tracked.  Without this logging, it may be impossible to track unauthorized access to the system.'
  desc 'check', 'Check the following log files to determine if access to the root account is being logged.  Try to su - and enter an incorrect password.
# more /var/adm/sulog
If root login accounts are not being logged, this is a finding.'
  desc 'fix', 'Update /etc/default/su and set SYSLOG=YES.

Ensure /etc/syslog.conf is configured to log auth.crit messages to capture all failed su attempts.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28641r482825_chk'
  tag severity: 'medium'
  tag gid: 'V-226480'
  tag rid: 'SV-226480r603265_rule'
  tag stig_id: 'GEN001060'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-28629r482826_fix'
  tag 'documentable'
  tag legacy: ['SV-39850', 'V-11980']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
