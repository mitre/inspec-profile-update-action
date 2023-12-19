control 'SV-38350' do
  title 'Local initialization files must not have extended ACLs.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', %q(Check user home directories for local initialization files with extended ACLs.
# ls `cat /etc/passwd | cut -f 6,6 -d ":" ` | grep "/home" | sort | uniq | xargs -n1 ls -alL 2>/dev/null | egrep "\.bash_logout|\.bash_profile|\.bashrc|\.cshrc|\.dispatch|\.dtprofile|\.emacs|\.env|\.exrc|\.login|\.logout|\.profile"

NOTE that the above command assumes the "base" of the user's home directory is "/home". If the system being checked uses a different "base", that "base" must be substituted for what is used in the above example.

If the permissions include a '+', the file has an extended ACL, this is a finding.)
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z [local initialization file with extended ACL]'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36390r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22362'
  tag rid: 'SV-38350r1_rule'
  tag stig_id: 'GEN001890'
  tag gtitle: 'GEN001890'
  tag fix_id: 'F-31731r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
