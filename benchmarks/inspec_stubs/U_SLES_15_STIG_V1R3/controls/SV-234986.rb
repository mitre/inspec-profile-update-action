control 'SV-234986' do
  title 'The SUSE operating system file integrity tool must be configured to verify Access Control Lists (ACLs).'
  desc 'ACLs can provide permissions beyond those permitted through the file mode and must be verified by file integrity tools.'
  desc 'check', 'Verify that the SUSE operating system file integrity tool is configured to verify extended attributes.

Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:

> zypper if aide | grep "Installed"

Installed: Yes

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.

If there is no application installed to perform integrity checks, this is a finding.

Check the "/etc/aide.conf" file to determine if the "xattrs" rule has been added to the rule list being applied to the files and directories selection lists.

An example rule that includes the "acl" rule follows:

All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux
/bin All > apply the custom rule to the files in bin 
/sbin All > apply the same custom rule to the files in sbin 

If the "acl" rule is not being used on all selection lines in the "/etc/aide.conf" file, or extended attributes are not being checked by another file integrity tool, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system file integrity tool to check file and directory ACLs. 

If AIDE is installed, ensure the "acl" rule is present on all file and directory selection lists.'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38174r619227_chk'
  tag severity: 'low'
  tag gid: 'V-234986'
  tag rid: 'SV-234986r622137_rule'
  tag stig_id: 'SLES-15-040040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38137r619228_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
