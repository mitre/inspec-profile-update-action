control 'SV-217151' do
  title 'The SUSE operating system file integrity tool must be configured to verify extended attributes.'
  desc 'Extended attributes in file systems are used to contain arbitrary data and file metadata with security implications.'
  desc 'check', 'Verify that the SUSE operating system file integrity tool is configured to verify extended attributes.

Check the "aide.conf" file to determine if the "xattrs" rule has been added to the rule list being applied to the files and directories selection lists.

An example rule that includes the "xattrs" rule follows:

     All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
     /bin All # apply the custom rule to the files in bin 
     /sbin All # apply the same custom rule to the files in sbin 

If the "xattrs" rule is not being used on all selection lines in the "/etc/aide.conf" file, or extended attributes are not being checked by another file integrity tool, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system file integrity tool to check file and directory extended attributes. 

If AIDE is installed, ensure the "xattrs" rule is present on all file and directory selection lists.'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18379r880940_chk'
  tag severity: 'low'
  tag gid: 'V-217151'
  tag rid: 'SV-217151r880941_rule'
  tag stig_id: 'SLES-12-010530'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18377r369610_fix'
  tag 'documentable'
  tag legacy: ['SV-91853', 'V-77157']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
