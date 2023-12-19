control 'SV-44905' do
  title 'The root accounts executable search path must be the vendor default and must contain only absolute paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables.  If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands.  This variable is formatted as a colon-separated list of directories.  If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory.  Entries starting with a slash (/) are absolute paths.'
  desc 'check', "To view the root user's PATH, log in as the root user, and execute:
# env | grep PATH
OR

# echo $PATH


This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. If an entry starts with a character other than a slash (/), this is a finding. If directories beyond those in the vendor's default root path are present. This is a finding."
  desc 'fix', "Edit the root user's local initialization files ~/.profile,~/.bashrc (assuming root shell is bash). Change any found PATH variable settings to the vendor's default path for the root user. Remove any empty path entries or references to relative paths."
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42344r1_chk'
  tag severity: 'medium'
  tag gid: 'V-776'
  tag rid: 'SV-44905r1_rule'
  tag stig_id: 'GEN000940'
  tag gtitle: 'GEN000940'
  tag fix_id: 'F-38336r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
