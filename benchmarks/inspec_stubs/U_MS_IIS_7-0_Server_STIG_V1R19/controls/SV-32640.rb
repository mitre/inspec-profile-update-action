control 'SV-32640' do
  title 'Java software installed on the production web server must be limited to .class files and the Java Virtual Machine.'
  desc "Source code for a Java program is, many times, stored in files with either .java or .jpp file extensions.  From the .java and .jpp files the Java compiler produces a binary file with an extension of .class. The .java or .jpp file could therefore reveal sensitive information regarding an application's logic and permissions to resources on the server."
  desc 'check', 'Search the system for files with either .java or .jpp extensions.  If files with .java or .jpp extensions are found, this is a finding.'
  desc 'fix', 'Remove all files from the web server with either .java and .jpp extensions.'
  impact 0.3
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32950r1_chk'
  tag severity: 'low'
  tag gid: 'V-2265'
  tag rid: 'SV-32640r2_rule'
  tag stig_id: 'WG490 IIS7'
  tag gtitle: 'WG490'
  tag fix_id: 'F-26836r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
