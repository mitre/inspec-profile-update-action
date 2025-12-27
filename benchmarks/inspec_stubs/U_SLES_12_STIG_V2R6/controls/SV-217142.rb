control 'SV-217142' do
  title 'There must be no shosts.equiv files on the SUSE operating system.'
  desc 'The shosts.equiv files are used to configure host-based authentication for the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', 'Verify there are no "shosts.equiv" files on the SUSE operating system.

Check the system for the existence of these files with the following command:

# find /etc -name shosts.equiv

If any "shosts.equiv" files are found on the system, this is a finding.'
  desc 'fix', 'Remove any "shosts.equiv" files found on the SUSE operating system.

# rm /[path]/[to]/[file]/shosts.equiv'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18370r369582_chk'
  tag severity: 'high'
  tag gid: 'V-217142'
  tag rid: 'SV-217142r603262_rule'
  tag stig_id: 'SLES-12-010410'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18368r369583_fix'
  tag 'documentable'
  tag legacy: ['V-77139', 'SV-91835']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
