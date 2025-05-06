control 'SV-221871' do
  title 'The Oracle Linux operating system must not contain shosts.equiv files.'
  desc 'The shosts.equiv files are used to configure host-based authentication for the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', 'Verify there are no "shosts.equiv" files on the system.

Check the system for the existence of these files with the following command:

# find / -name shosts.equiv

If any "shosts.equiv" files are found on the system, this is a finding.'
  desc 'fix', 'Remove any found "shosts.equiv" files from the system.

# rm /[path]/[to]/[file]/shosts.equiv'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23586r419685_chk'
  tag severity: 'high'
  tag gid: 'V-221871'
  tag rid: 'SV-221871r603260_rule'
  tag stig_id: 'OL07-00-040550'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23575r419686_fix'
  tag 'documentable'
  tag legacy: ['SV-108585', 'V-99481']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
