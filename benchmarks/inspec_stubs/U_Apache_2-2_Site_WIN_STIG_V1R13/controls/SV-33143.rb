control 'SV-33143' do
  title 'Java software on production web servers must be limited to class files and the JAVA virtual machine.'
  desc 'From the source code in a .java or a .jpp file, the Java compiler produces a binary file with an extension of .class. The .java or .jpp file would, therefore, reveal sensitive information regarding an application’s logic and permissions to resources on the server. By contrast, the .class file, because it is intended to be machine independent, is referred to as bytecode. Bytecodes are run by the Java Virtual Machine (JVM), or the Java Runtime Environment (JRE), via a browser configured to permit Java code.'
  desc 'check', 'Search the web content and scripts directories (found in check WG290) for .java and .jpp files.

If either file type is found, this is a finding.

Note: Executables such as java.exe, jre.exe, and jrew.exe are permitted.'
  desc 'fix', 'Remove the appropriate files from the web server.'
  impact 0.3
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33794r1_chk'
  tag severity: 'low'
  tag gid: 'V-2265'
  tag rid: 'SV-33143r1_rule'
  tag stig_id: 'WG490 W22'
  tag gtitle: 'WG490'
  tag fix_id: 'F-29438r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
