control 'SV-33062' do
  title 'All utility programs, not necessary for operations, must be removed or disabled.'
  desc 'Just as running unneeded services and protocols is a danger to the web server at the lower levels of the OSI model, running unneeded utilities and programs is also a danger at the application layer of the OSI model. Office suites, development tools, and graphical editors are examples of such programs that are troublesome. Individual productivity tools have no legitimate place or use on an enterprise, production web server and they are also prone to their own security risks.'
  desc 'check', 'Query the ISSO, the SA, the web administrator, or developers as necessary to determine if the web server is configured with unnecessary software. 

Query the SA to determine if processes other than those that support the web server are loaded and/or run on the web server. 

Examples of software that should not be on the web server are all web development tools, office suites (unless the web server is a private web development server), compilers, and other utilities that are not part of the web server suite or the basic operating system. 

1) Check the directory structure of the server and ensure that additional, unintended, or unneeded applications are not loaded on the system. 

2) Start >> All Programs >> check for programs services such as:
Front Page
MS Access
MS Excel
MS Money
MS Word
Third-party text editors
Graphics editors

If, after review of the application on the system, the SA cannot provide justification for the requirement of the identified software, this is a finding.'
  desc 'fix', 'Install only web support software on the web server. When other processes are supported by the web server, ensure that a risk assessment has been performed and documented. If a database server is installed on the same platform as the web server, it must be on a separate drive or partition. Remove all unnecessary applications and programs.'
  impact 0.3
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33735r2_chk'
  tag severity: 'low'
  tag gid: 'V-2251'
  tag rid: 'SV-33062r2_rule'
  tag stig_id: 'WG130 W22'
  tag gtitle: 'WG130'
  tag fix_id: 'F-29370r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
