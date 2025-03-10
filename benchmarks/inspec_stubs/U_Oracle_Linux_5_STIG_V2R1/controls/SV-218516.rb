control 'SV-218516' do
  title 'The rexec daemon must not be running.'
  desc 'The rexecd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', '# grep disable /etc/xinetd.d/rexec
If the service file exists and is not disabled, this is a finding.'
  desc 'fix', 'Edit /etc/xinetd.d/rexec and set "disable=yes"'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19991r562672_chk'
  tag severity: 'high'
  tag gid: 'V-218516'
  tag rid: 'SV-218516r603259_rule'
  tag stig_id: 'GEN003840'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-19989r562673_fix'
  tag 'documentable'
  tag legacy: ['V-4688', 'SV-64037']
  tag cci: ['CCI-000381', 'CCI-001435']
  tag nist: ['CM-7 a', 'AC-17 (8)']
end
