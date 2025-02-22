control 'SV-35166' do
  title 'The system package management tool must be used to verify system software periodically.'
  desc 'Verification using the system package management tool can be used to determine that system software has not been tampered with.

This requirement is not applicable to systems that do not use package management tools.'
  desc 'check', %q(Check the root crontab for a job invoking the system package management tool to verify the integrity of installed packages. If no such job exists, this is a finding.

An example using HP's command line tool suite to list/verify installed local machine software bundles is:
# swlist -l bundle
# Initializing...
# Contacting target "abc123"...
#
# Target: abc123:/
#
10GigEthr-00 B.11.31.0709 PCI-X 10 Gigabit Ethernet;Supptd 

Then run swverify, at the end of the output look for status of Verification succeeded.
# swverify -v 10GigEthr-00)
  desc 'fix', 'Add a job to the root crontab invoking the system package management tool to verify the integrity of installed packages.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35018r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22506'
  tag rid: 'SV-35166r1_rule'
  tag stig_id: 'GEN006565'
  tag gtitle: 'GEN006565'
  tag fix_id: 'F-32107r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000366', 'CCI-000698']
  tag nist: ['CM-6 b', 'SA-10 (1)']
end
