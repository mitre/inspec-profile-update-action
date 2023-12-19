control 'SV-218364' do
  title 'The owner, group-owner, mode, ACL, and location of files with the setuid bit set must be documented using site-defined procedures.'
  desc 'All files with the setuid bit set will allow anyone running these files to be temporarily assigned the UID of the file. While many system files depend on these attributes for proper operation, security problems can result if setuid is assigned to programs allowing reading and writing of files, or shell escapes. Only default vendor-supplied executables should have the setuid bit set.'
  desc 'check', 'Check for the presence of aide on the system:
# rpm -qa | grep aide

If aide is not installed, ask the SA what file integrity tool is being used to check the system.

Check the global crontabs for the presence of an "aide" job to run at least weekly, if "aide" is installed. Otherwise, check for the presence of a "cron" job to run the alternate file integrity checking application.

# grep aide /etc/cron*/*

If a tool is being run, then the configuration file for the appropriate tool needs to be checked for selection lines /bin, /sbin, /lib, and /usr.

If the file integrity tool is set to check "setuid" and "setgid", this is not a finding.

List all "setuid" files on the system.

Procedure:
# find / -perm -4000 -exec ls -l {} \\; | more

Note: Executing these commands may result in large listings of files; the output may be redirected to a file for easier analysis.

Ask the SA or ISSO if files with the setuid bit set have been documented. Documentation must include the owner, group-owner, mode, ACL, and location of the files.

If any undocumented file has its setuid bit set, this is a finding.'
  desc 'fix', 'Document the files with the suid bit set or unset the suid bit on the executable.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19839r569050_chk'
  tag severity: 'medium'
  tag gid: 'V-218364'
  tag rid: 'SV-218364r603259_rule'
  tag stig_id: 'GEN002380'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19837r569051_fix'
  tag 'documentable'
  tag legacy: ['V-801', 'SV-63399']
  tag cci: ['CCI-000366', 'CCI-000368']
  tag nist: ['CM-6 b', 'CM-6 c']
end
