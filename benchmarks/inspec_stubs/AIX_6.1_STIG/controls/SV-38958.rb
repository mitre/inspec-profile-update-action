control 'SV-38958' do
  title 'The system package management tool must be used to verify system software periodically.'
  desc 'Verification using the system package management tool can be used to determine that system software has not been tampered with.

This requirement is not applicable to systems that do not use package management tools.'
  desc 'check', 'Check the root crontab for a job invoking the system package management tool to verify the integrity of installed packages. 

# crontab -l | grep lppchk

If no such job exists, this is a finding.'
  desc 'fix', 'Add a job to the root crontab invoking the system package management tool to verify the integrity of installed packages.  

# lppchk -c'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38242r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22506'
  tag rid: 'SV-38958r1_rule'
  tag stig_id: 'GEN006565'
  tag gtitle: 'GEN006565'
  tag fix_id: 'F-32343r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000366', 'CCI-000698']
  tag nist: ['CM-6 b', 'SA-10 (1)']
end
