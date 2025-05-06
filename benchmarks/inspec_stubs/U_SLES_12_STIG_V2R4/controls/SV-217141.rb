control 'SV-217141' do
  title 'There must be no .shosts files on the SUSE operating system.'
  desc 'The .shosts files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', %q(Verify there are no ".shosts" files on the SUSE operating system.

Check the system for the existence of these files with the following command:

# find / -name '.shosts'

If any ".shosts" files are found on the system, this is a finding.)
  desc 'fix', 'Remove any ".shosts" files found on the SUSE operating system.

# rm /[path]/[to]/[file]/.shosts'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18369r369579_chk'
  tag severity: 'high'
  tag gid: 'V-217141'
  tag rid: 'SV-217141r603262_rule'
  tag stig_id: 'SLES-12-010400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18367r369580_fix'
  tag 'documentable'
  tag legacy: ['V-77137', 'SV-91833']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
