control 'SV-216288' do
  title 'The NIS package must not be installed.'
  desc 'NIS is an insecure protocol.'
  desc 'check', 'Determine if the NIS package is installed.

# pkg list service/network/nis

If an installed package named "service/network/nis" is listed, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

# pfexec pkg uninstall service/network/nis'
  impact 0.7
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17524r370952_chk'
  tag severity: 'high'
  tag gid: 'V-216288'
  tag rid: 'SV-216288r603267_rule'
  tag stig_id: 'SOL-11.1-020110'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17522r370953_fix'
  tag 'documentable'
  tag legacy: ['SV-60777', 'V-47905']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
