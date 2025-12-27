control 'SV-226980' do
  title 'The /etc/syslog.conf file must be owned by root.'
  desc 'If the /etc/syslog.conf file is not owned by root, unauthorized users could be allowed to view, edit, or delete important system messages handled by the syslog facility.'
  desc 'check', 'Check /etc/syslog.conf ownership.

# ls -lL /etc/syslog.conf

If /etc/syslog.conf is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to set the owner to root.
# chown root /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29142r485270_chk'
  tag severity: 'medium'
  tag gid: 'V-226980'
  tag rid: 'SV-226980r603265_rule'
  tag stig_id: 'GEN005400'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29130r485271_fix'
  tag 'documentable'
  tag legacy: ['V-4393', 'SV-4393']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
