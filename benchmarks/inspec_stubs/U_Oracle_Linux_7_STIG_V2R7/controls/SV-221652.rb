control 'SV-221652' do
  title 'The Oracle Linux operating system must be configured so that the file permissions, ownership, and group membership of system files and commands match the vendor values.'
  desc 'Discretionary access control is weakened if a user or group has access permissions to system files and directories greater than the default.

'
  desc 'check', %q(Verify the file permissions, ownership, and group membership of system files and commands match the vendor values.

Check the default file permissions, ownership, and group membership of system files and commands with the following command:

# for i in `rpm -Va | egrep '^.{1}M|^.{5}U|^.{6}G' | cut -d "" "" -f 4,5`;do for j in `rpm -qf $i`;do rpm -ql $j --dump | cut -d "" "" -f 1,5,6,7 | grep $i;done;done
/var/log/gdm 040755 root root
/etc/audisp/audisp-remote.conf 0100640 root root
/usr/bin/passwd 0104755 root root

For each file returned, verify the current permissions, ownership, and group membership:
# ls -la <filename>
-rw-------. 1 root root 133 Jan 11 13:25 /etc/audisp/audisp-remote.conf

If the file is more permissive than the default permissions, this is a finding.

If the file is not owned by the default owner and is not documented with the Information System Security Officer (ISSO), this is a finding.

If the file is not a member of the default group and is not documented with the ISSO, this is a finding.)
  desc 'fix', 'Run the following command to determine which package owns the file:

# rpm -qf <filename>

Reset the user and group ownership of files within a package with the following command:

# rpm --setugids <packagename>

Reset the permissions of files within a package with the following command:

# rpm --setperms <packagename>'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36264r646953_chk'
  tag severity: 'high'
  tag gid: 'V-221652'
  tag rid: 'SV-221652r646955_rule'
  tag stig_id: 'OL07-00-010010'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-36228r646954_fix'
  tag satisfies: ['SRG-OS-000257-GPOS-00098', 'SRG-OS-000278-GPOS-00108']
  tag 'documentable'
  tag legacy: ['V-99045', 'SV-108149']
  tag cci: ['CCI-001494', 'CCI-001496']
  tag nist: ['AU-9', 'AU-9 (3)']
end
