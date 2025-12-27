control 'SV-226421' do
  title 'Hidden extended file attributes must not exist on the system.'
  desc 'Solaris extended attributes are essentially files themselves that are of an arbitrary size and content.  They could be used to hide files from ordinary system file scans.'
  desc 'check', 'Search for all files with hidden extended attributes.

# find / -xattr -print -exec runat {} ls -al \\;

If hidden extended file attributes exist, this is a finding.'
  desc 'fix', 'Remove the hidden extended file attributes.
# runat <file name> rm <attribute name>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28582r482624_chk'
  tag severity: 'medium'
  tag gid: 'V-226421'
  tag rid: 'SV-226421r603265_rule'
  tag stig_id: 'GEN000000-SOL00420'
  tag gtitle: 'SRG-OS-000016'
  tag fix_id: 'F-28570r482625_fix'
  tag 'documentable'
  tag legacy: ['SV-12533', 'V-12032']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
