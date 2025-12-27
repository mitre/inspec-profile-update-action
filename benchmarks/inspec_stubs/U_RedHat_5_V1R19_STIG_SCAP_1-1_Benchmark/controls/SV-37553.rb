control 'SV-37553' do
  title 'Device files and directories must only be writable by users with a system account or as configured by the vendor.'
  desc 'System device files in writable directories could be modified, removed, or used by an unprivileged user to control system hardware.'
  desc 'fix', 'Remove the world-writable permission from the device file(s).

Procedure:
# chmod o-w <device file>

Document all changes.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-924'
  tag rid: 'SV-37553r3_rule'
  tag stig_id: 'GEN002280'
  tag gtitle: 'GEN002280'
  tag fix_id: 'F-31464r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
