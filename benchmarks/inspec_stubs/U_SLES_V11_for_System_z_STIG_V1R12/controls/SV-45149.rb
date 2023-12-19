control 'SV-45149' do
  title 'Global initialization files lists of preloaded libraries must contain only absolute paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary.  If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.  This variable is formatted as a space-separated list of libraries.  Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Check the global initialization files' library preload list.
# grep -r LD_PRELOAD /etc/bash.bashrc /etc/csh.cshrc /etc/csh.login /etc/environment /etc/ksh.kshrc /etc/profile /etc/profile.d/* /etc/zshrc

This variable is formatted as a colon-separated list of paths. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. If an entry begins with a character other than a slash (/) this is a relative path, this is a finding."
  desc 'fix', 'Edit the global initialization file and remove the relative path entry from the library preload variable.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42491r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22360'
  tag rid: 'SV-45149r1_rule'
  tag stig_id: 'GEN001850'
  tag gtitle: 'GEN001850'
  tag fix_id: 'F-38545r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
