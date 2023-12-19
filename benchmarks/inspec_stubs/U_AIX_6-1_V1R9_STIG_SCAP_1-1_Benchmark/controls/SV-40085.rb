control 'SV-40085' do
  title 'The root accounts executable search path must be the vendor default and must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Entries starting with a slash (/) are absolute paths.'
  desc 'fix', "Edit the root user's local initialization files and remove any relative path entries that have not been documented with the ISSO.

Edit the root user’s local initialization files and remove any empty entry that is defined.

# cd <root's home directory>
# vi .profile .cshrc

If the bash shell is installed, edit these additional files.
# vi .bashrc .bash_profile"
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-776'
  tag rid: 'SV-40085r3_rule'
  tag stig_id: 'GEN000940'
  tag gtitle: 'GEN000940'
  tag fix_id: 'F-34156r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
