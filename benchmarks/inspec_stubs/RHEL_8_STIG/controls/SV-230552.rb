control 'SV-230552' do
  title 'The RHEL 8 file integrity tool must be configured to verify Access Control Lists (ACLs).'
  desc 'ACLs can provide permissions beyond those permitted through the file mode and must be verified by file integrity tools.

RHEL 8 installation media come with a file integrity tool, Advanced Intrusion Detection Environment (AIDE).'
  desc 'check', 'Verify the file integrity tool is configured to verify ACLs.

Note: AIDE is highly configurable at install time. This requirement assumes the "aide.conf" file is under the "/etc" directory.

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.

Use the following command to determine if the file is in a location other than "/etc/aide/aide.conf":

$ sudo find / -name aide.conf

Check the "aide.conf" file to determine if the "acl" rule has been added to the rule list being applied to the files and directories selection lists with the following command:

$ sudo egrep "[+]?acl" /etc/aide.conf

VarFile = OwnerMode+n+l+X+acl

If the "acl" rule is not being used on all selection lines in the "/etc/aide.conf" file, is commented out, or ACLs are not being checked by another file integrity tool, this is a finding.'
  desc 'fix', 'Configure the file integrity tool to check file and directory ACLs. 

If AIDE is installed, ensure the "acl" rule is present on all file and directory selection lists.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33221r568402_chk'
  tag severity: 'low'
  tag gid: 'V-230552'
  tag rid: 'SV-230552r627750_rule'
  tag stig_id: 'RHEL-08-040310'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33196r568403_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
