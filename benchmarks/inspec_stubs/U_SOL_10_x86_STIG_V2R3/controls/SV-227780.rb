control 'SV-227780' do
  title 'Process core dumps must be disabled unless needed.'
  desc 'Process core dumps contain the memory in use by the process when it crashed.  Process core dump files can be of significant size and their use can result in file systems filling to capacity, which may result in Denial of Service.  Process core dumps can be useful for software debugging.'
  desc 'check', 'Check the process core dump configuration.
# coreadm |grep enabled
OR
# egrep "COREADM_.*_ENABLED" /etc/coreadm.conf.

If any lines are returned by coreadm or if any lines are not set to no in /etc/coreadm.conf, this is a finding.

# grep coredumpsize /etc/system
If the value is 1, this is a finding.'
  desc 'fix', 'Change the process core dump configuration.
# coreadm -d global
# coreadm -d process
# coreadm -d global-setid
# coreadm -d proc-setid
# coreadm -d log

Edit /etc/system and remove the coredumpsize parameter.'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29942r489694_chk'
  tag severity: 'low'
  tag gid: 'V-227780'
  tag rid: 'SV-227780r603266_rule'
  tag stig_id: 'GEN003500'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29930r489695_fix'
  tag 'documentable'
  tag legacy: ['V-11996', 'SV-27400']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
