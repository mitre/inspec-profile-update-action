control 'SV-33032' do
  title 'Java software on production web servers must be limited to class files and the JAVA virtual machine.'
  desc 'From the source code in a .java or a .jpp file, the Java compiler produces a binary file with an extension of .class. The .java or .jpp file would, therefore, reveal sensitive information regarding an application’s logic and permissions to resources on the server. By contrast, the .class file, because it is intended to be machine independent, is referred to as bytecode. Bytecodes are run by the Java Virtual Machine (JVM), or the Java Runtime Environment (JRE), via a browser configured to permit Java code.'
  desc 'check', 'Enter the commands: 

find / -name *.java 

find / -name *.jpp 

If either file type is found, this is a finding.'
  desc 'fix', 'Remove the unnecessary files from the web server.'
  impact 0.3
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33715r1_chk'
  tag severity: 'low'
  tag gid: 'V-2265'
  tag rid: 'SV-33032r1_rule'
  tag stig_id: 'WG490 A22'
  tag gtitle: 'WG490'
  tag fix_id: 'F-29347r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
