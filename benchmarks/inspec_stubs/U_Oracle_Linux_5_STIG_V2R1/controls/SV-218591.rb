control 'SV-218591' do
  title 'The /etc/syslog.conf file must be owned by root.'
  desc 'If the /etc/syslog.conf file is not owned by root, unauthorized users could be allowed to view, edit, or delete important system messages handled by the syslog facility.'
  desc 'check', 'Check /etc/syslog.conf or /etc/rsyslog.conf ownership:

For syslog:

# ls -lL /etc/syslog.conf

For rsyslog:

# ls -lL /etc/rsyslog.conf

If /etc/syslog.conf or /etc/rsyslog.conf is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to set the owner to root.

# chown root /etc/syslog.conf
 
Or:

# chown root /etc/rsyslog.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20066r555971_chk'
  tag severity: 'medium'
  tag gid: 'V-218591'
  tag rid: 'SV-218591r603259_rule'
  tag stig_id: 'GEN005400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20064r555972_fix'
  tag 'documentable'
  tag legacy: ['V-4393', 'SV-63473']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
