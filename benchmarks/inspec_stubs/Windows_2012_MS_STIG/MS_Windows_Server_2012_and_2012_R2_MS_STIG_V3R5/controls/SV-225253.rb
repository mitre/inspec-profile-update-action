control 'SV-225253' do
  title 'Backups of system-level information must be protected.'
  desc 'A system backup will usually include sensitive information such as user accounts that could be used in an attack.  As a valuable system resource, the system backup must be protected and stored in a physically secure location.'
  desc 'check', 'Determine if system-level information backups are protected from destruction and stored in a physically secure location.  If they are not, this is a finding.'
  desc 'fix', 'Ensure system-level information backups are stored in a secure location and protected from destruction.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26952r471101_chk'
  tag severity: 'low'
  tag gid: 'V-225253'
  tag rid: 'SV-225253r569185_rule'
  tag stig_id: 'WN12-00-000016'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-26940r471102_fix'
  tag 'documentable'
  tag legacy: ['V-40172', 'SV-52130']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
