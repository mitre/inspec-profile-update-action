control 'SV-220017' do
  title 'The ASET master files must be located in the /usr/aset/masters directory.'
  desc 'If ASET is used and the master files (tune.high, tune.med, tune.low, and uid_aliases) are not located in the proper place, ASET cannot operate correctly and valuable security findings could be lost.'
  desc 'check', 'Verify ASET is being used.

# crontab -l |grep aset 

If there is an output, then check to make sure the files in question are in the /usr/aset/masters directory.

# ls -l /usr/aset/masters

The following files should be in the listing: tune.high, tune.low, tune.med, and uid_aliases. If any of the files are not in the directory listing, this is a finding.'
  desc 'fix', 'Install the default ASET configuration files.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36359r602680_chk'
  tag severity: 'medium'
  tag gid: 'V-220017'
  tag rid: 'SV-220017r603265_rule'
  tag stig_id: 'GEN000000-SOL00120'
  tag gtitle: 'SRG-OS-000016'
  tag fix_id: 'F-36323r602681_fix'
  tag 'documentable'
  tag legacy: ['SV-36751', 'V-4313']
  tag cci: ['CCI-000032', 'CCI-000225']
  tag nist: ['AC-4 (8) (a)', 'AC-6']
end
