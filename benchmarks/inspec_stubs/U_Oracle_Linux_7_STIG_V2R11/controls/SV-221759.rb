control 'SV-221759' do
  title 'The Oracle Linux operating system must be configured so that the file integrity tool is configured to verify Access Control Lists (ACLs).'
  desc 'ACLs can provide permissions beyond those permitted through the file mode and must be verified by file integrity tools.'
  desc 'check', 'Verify the file integrity tool is configured to verify ACLs.

Note: AIDE is highly configurable at install time. These commands assume the "aide.conf" file is under the "/etc" directory. 

Use the following command to determine if the file is in another location:

     # find / -name aide.conf

Check the "aide.conf" file to determine if the "acl" rule has been added to the rule list being applied to the files and directories selection lists.

An example rule that includes the "acl" rule is below:

     All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
     /bin All # apply the custom rule to the files in bin 
     /sbin All # apply the same custom rule to the files in sbin 

If the "acl" rule is not being used on all uncommented selection lines in the "/etc/aide.conf" file, or ACLs are not being checked by another file integrity tool, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to check file and directory ACLs. 

If AIDE is installed, ensure the "acl" rule is present on all uncommented file and directory selection lists.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23474r880694_chk'
  tag severity: 'low'
  tag gid: 'V-221759'
  tag rid: 'SV-221759r880695_rule'
  tag stig_id: 'OL07-00-021600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23463r419350_fix'
  tag 'documentable'
  tag legacy: ['V-99257', 'SV-108361']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
