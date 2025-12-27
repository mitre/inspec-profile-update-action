control 'SV-215247' do
  title 'AIX must start audit at boot.'
  desc 'If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Check if /etc/rc contains the following line:
/usr/sbin/audit start

# grep "audit start" /etc/rc
/usr/sbin/audit start

If a result is not returned, this is a finding.'
  desc 'fix', "To start auditing at system startup, add the following line to the /etc/rc file, just prior to the line reading dspmsg rc.cat 5 'Multi-user initialization completed':
/usr/sbin/audit start

Symmetrically  add the '/usr/sbin/audit shutdown' command to /etc/rc.shutdown."
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16445r294192_chk'
  tag severity: 'medium'
  tag gid: 'V-215247'
  tag rid: 'SV-215247r508663_rule'
  tag stig_id: 'AIX7-00-002023'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag fix_id: 'F-16443r294193_fix'
  tag 'documentable'
  tag legacy: ['V-91463', 'SV-101561']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
