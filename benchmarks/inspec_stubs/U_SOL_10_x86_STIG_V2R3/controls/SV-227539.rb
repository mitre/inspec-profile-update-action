control 'SV-227539' do
  title 'If the system is a firewall, ASET must be used on the system, and the firewall parameters must be set in /usr/aset/asetenv.'
  desc 'ASET will not perform firewall tasks if it is not listed as a parameter in /usr/aset/asetenv.'
  desc 'check', 'Perform the following to determine if ASET is being used.

	# crontab -l |grep aset

A returned entry would indicate ASET is being utilized.  Determine if ASET is configured to check firewall settings.

	# grep TASKS /usr/aset/asetenv | grep firewall

If an entry is not returned, this is a finding.'
  desc 'fix', 'If the system is used as a firewall and ASET is used, ensure the firewall parameter is configured in /usr/aset/asetenv.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29701r488147_chk'
  tag severity: 'medium'
  tag gid: 'V-227539'
  tag rid: 'SV-227539r603266_rule'
  tag stig_id: 'GEN000000-SOL00160'
  tag gtitle: 'SRG-OS-000016'
  tag fix_id: 'F-29689r488148_fix'
  tag 'documentable'
  tag legacy: ['V-4309', 'SV-4309']
  tag cci: ['CCI-000032', 'CCI-000366']
  tag nist: ['AC-4 (8) (a)', 'CM-6 b']
end
