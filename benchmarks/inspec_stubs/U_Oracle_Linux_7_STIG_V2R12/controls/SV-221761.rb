control 'SV-221761' do
  title 'The Oracle Linux operating system must use a file integrity tool that is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.'
  desc 'File integrity tools use cryptographic hashes for verifying file contents and directories have not been altered. These hashes must be FIPS 140-2 approved cryptographic hashes.
The Oracle Linux operating system installation media ships with an optional file integrity tool called Advanced Intrusion Detection Environment (AIDE). AIDE is highly configurable at install time. This requirement assumes the "aide.conf" file is under the "/etc" directory.'
  desc 'check', 'Verify the file integrity tool is configured to use FIPS 140-2-approved cryptographic hashes for validating file contents and directories.

Note: AIDE is highly configurable at install time. These commands assume the "aide.conf" file is under the "/etc" directory. 

Use the following command to determine if the file is in another location:

     # find / -name aide.conf

Check the "aide.conf" file to determine if the "sha512" rule has been added to the rule list being applied to the files and directories selection lists. Exclude any log files, or files expected to change frequently, to reduce unnecessary notifications.

An example rule that includes the "sha512" rule follows:
 
     All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
     /bin All # apply the custom rule to the files in bin 
     /sbin All # apply the same custom rule to the files in sbin 

If the "sha512" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or another file integrity tool is not using FIPS 140-2-approved cryptographic hashes for validating file contents and directories, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to use FIPS 140-2 cryptographic hashes for validating file and directory contents. 

If AIDE is installed, ensure the "sha512" rule is present on all uncommented file and directory selection lists. Exclude any log files, or files expected to change frequently, to reduce unnecessary notifications.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36285r880698_chk'
  tag severity: 'medium'
  tag gid: 'V-221761'
  tag rid: 'SV-221761r880699_rule'
  tag stig_id: 'OL07-00-021620'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36249r792799_fix'
  tag 'documentable'
  tag legacy: ['V-99261', 'SV-108365']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
