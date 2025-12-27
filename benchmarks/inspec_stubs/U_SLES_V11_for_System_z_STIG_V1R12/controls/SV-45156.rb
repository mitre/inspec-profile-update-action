control 'SV-45156' do
  title 'Local initialization files must not have extended ACLs.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', "Check user home directories for local initialization files with extended ACLs.
# for HOMEDIR in $(cut -d: -f6 /etc/passwd); do find ${HOMEDIR} -type f -name '\\.*' | xargs ls -ld | grep '\\+'; done

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all <local initialization file with extended ACL>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42499r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22362'
  tag rid: 'SV-45156r1_rule'
  tag stig_id: 'GEN001890'
  tag gtitle: 'GEN001890'
  tag fix_id: 'F-38552r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
