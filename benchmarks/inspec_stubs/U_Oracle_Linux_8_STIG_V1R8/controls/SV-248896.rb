control 'SV-248896' do
  title 'The OL 8 file integrity tool must be configured to verify extended attributes.'
  desc 'Extended attributes in file systems are used to contain arbitrary data and file metadata with security implications. 
 
OL 8 installation media come with a file integrity tool, Advanced Intrusion Detection Environment (AIDE).'
  desc 'check', 'Verify the file integrity tool is configured to verify extended attributes. 
 
If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 
 
Note: AIDE is highly configurable at install time. This requirement assumes the "aide.conf" file is under the "/etc" directory. 
 
Use the following command to determine if the file is in another location: 
 
$ sudo find / -name aide.conf 
 
Check the "aide.conf" file to determine if the "xattrs" rule has been added to the rule list being applied to the files and directories selection lists. 
 
An example rule that includes the "xattrs" rule follows: 
 
All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux 
/bin All # apply the custom rule to the files in bin 
/sbin All # apply the same custom rule to the files in sbin 
 
If the "xattrs" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or extended attributes are not being checked by another file integrity tool, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to check file and directory extended attributes. 
 
If AIDE is installed, ensure the "xattrs" rule is present on all uncommented file and directory selection lists.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52330r780252_chk'
  tag severity: 'low'
  tag gid: 'V-248896'
  tag rid: 'SV-248896r780254_rule'
  tag stig_id: 'OL08-00-040300'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52284r780253_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
