control 'SV-976' do
  title 'Cron must not execute group-writable or world-writable programs.'
  desc 'If cron executes group-writable or world-writable programs, there is a possibility that unauthorized users could manipulate the programs with malicious intent.  This could compromise system and network security.'
  desc 'check', 'List all cron jobs on the system.  If any cron job executes a program with group-writable or world-writable permissions, this is a finding.'
  desc 'fix', 'Remove the world-writable and group-writable permissions from the cron program file(s) identified.
# chmod go-w <cron program file>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-788r2_chk'
  tag severity: 'medium'
  tag gid: 'V-976'
  tag rid: 'SV-976r2_rule'
  tag stig_id: 'GEN003000'
  tag gtitle: 'GEN003000'
  tag fix_id: 'F-1130r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
