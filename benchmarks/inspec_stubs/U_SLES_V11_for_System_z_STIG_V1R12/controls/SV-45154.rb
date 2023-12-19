control 'SV-45154' do
  title 'All local initialization files must have mode 0740 or less permissive.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', "Check the modes of local initialization files.

Procedure:
# for HOMEDIR in $(cut -d: -f6 /etc/passwd); do find ${HOMEDIR} ! -fstype nfs -type f -name '\\.*' \\( -perm -0002 -o -perm -0020 \\); done

If local initialization files are more permissive than 0740 or the .dt directory is more permissive than 0755 or the .dtprofile file is more permissive than 0755, this is a finding."
  desc 'fix', "Ensure user startup files have permissions of 0740 or more restrictive. Examine each user’s home directory and verify all file names beginning with “.” have access permissions of 0740 or more restrictive. If they do not, use the chmod command to correct the vulnerability. 

Procedure: 
# chmod 0740 .filename 

Note: The period is part of the file name and is required.   
     OR
# for HOMEDIR in $(cut -d: -f6 /etc/passwd); do FILES=$(find ${HOMEDIR} ! -fstype nfs -type f -name '\\.*' \\( -perm -0002 -o -perm -0020 \\) ); for INIFILE in ${FILES}; do chmod 600 ${INIFILE}; done; done"
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42497r1_chk'
  tag severity: 'medium'
  tag gid: 'V-905'
  tag rid: 'SV-45154r1_rule'
  tag stig_id: 'GEN001880'
  tag gtitle: 'GEN001880'
  tag fix_id: 'F-38550r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
