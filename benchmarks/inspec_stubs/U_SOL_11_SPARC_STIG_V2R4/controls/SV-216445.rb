control 'SV-216445' do
  title 'Process core dumps must be disabled unless needed.'
  desc 'Process core dumps contain the memory in use by the process when it crashed. Process core dump files can be of significant size and their use can result in file systems filling to capacity, which may result in denial of service. Process core dumps can be useful for software debugging.'
  desc 'check', 'Check the process core dump configuration.
# coreadm | grep enabled

If any lines are returned by coreadm other than "logging", this is a finding.'
  desc 'fix', 'The Maintenance and Repair profile is required.

Change the process core dump configuration to disable core dumps globally and on a per process basis.

# coreadm -d global
# coreadm -d process
# coreadm -d global-setid
# coreadm -d proc-setid
# coreadm -e log'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17681r371423_chk'
  tag severity: 'medium'
  tag gid: 'V-216445'
  tag rid: 'SV-216445r603267_rule'
  tag stig_id: 'SOL-11.1-080040'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17679r371424_fix'
  tag 'documentable'
  tag legacy: ['SV-60893', 'V-48021']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
