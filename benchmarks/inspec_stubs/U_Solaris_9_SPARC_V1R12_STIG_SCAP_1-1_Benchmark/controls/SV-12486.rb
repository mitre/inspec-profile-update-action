control 'SV-12486' do
  title "All global initialization files' executable search paths must contain only absolute paths."
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables.  If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands.  This variable is formatted as a colon-separated list of directories.  If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory.  Paths starting with a slash (/) are absolute paths.'
  desc 'fix', 'Edit the global initialization file(s) with PATH variables containing relative paths.  Edit the file and remove the relative path from the PATH variable.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-11985'
  tag rid: 'SV-12486r2_rule'
  tag stig_id: 'GEN001840'
  tag gtitle: 'GEN001840'
  tag fix_id: 'F-11246r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-2, ECCD-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
