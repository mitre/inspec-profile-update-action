control 'SV-218801' do
  title 'Java software installed on a production IIS 10.0 web server must be limited to .class files and the Java Virtual Machine.'
  desc "Mobile code in hosted applications allows the developer to add functionality and displays to hosted applications that are fluid, as opposed to a static web page. The data presentation becomes more appealing to the user, is easier to analyze, and is less complicated to navigate through the hosted application and data.

Some mobile code technologies in use in today's applications are: Java, JavaScript, ActiveX, PDF, Postscript, Shockwave movies, Flash animations, and VBScript. The DoD has created policies that define the usage of mobile code on DoD systems. The usage restrictions and implementation guidance apply to both the selection and use of mobile code installed on organizational servers and mobile code downloaded and executed on individual workstations.

Source code for a Java program is often stored in files with either .java or .jpp file extensions. From the .java and .jpp files the Java compiler produces a binary file with an extension of .class. The .java or .jpp file could therefore reveal sensitive information regarding an application's logic and permissions to resources on the server."
  desc 'check', 'Search the system for files with either .java or .jpp extensions.

If files with .java or .jpp extensions are found, this is a finding.'
  desc 'fix', 'Remove all files from the web server with both .java and .jpp extensions.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20273r310878_chk'
  tag severity: 'medium'
  tag gid: 'V-218801'
  tag rid: 'SV-218801r561041_rule'
  tag stig_id: 'IIST-SV-000130'
  tag gtitle: 'SRG-APP-000206-WSR-000128'
  tag fix_id: 'F-20271r310879_fix'
  tag 'documentable'
  tag legacy: ['SV-109241', 'V-100137']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
