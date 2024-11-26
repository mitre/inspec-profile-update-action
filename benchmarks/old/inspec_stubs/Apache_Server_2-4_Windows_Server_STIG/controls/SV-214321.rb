control 'SV-214321' do
  title 'The Apache web server must provide install options to exclude the installation of documentation, sample code, example applications, and tutorials.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server because this type of code has not been evaluated and approved. A production web server must only contain components that are operationally necessary (e.g., compiled code, scripts, web-content, etc.).

Any documentation, sample code, example applications, and tutorials must be removed from a production web server. To ensure that the documentation and code are not installed or uninstalled completely, the web server must offer an option as part of the installation process to exclude these packages or to uninstall the packages if necessary.

'
  desc 'check', "If the site requires the use of a particular piece of software, the Information System Security Officer (ISSO) will need to maintain documentation identifying this software as necessary for operations. The software must be operated at the vendor's current patch level and must be a supported vendor release.

If programs or utilities that meet the above criteria are installed on the web server, and appropriate documentation and signatures are in evidence, this is not a finding.

Determine whether the web server is configured with unnecessary software.

Determine whether processes other than those that support the web server are loaded and/or run on the web server.

Examples of software that should not be on the web server are all web development tools, office suites (unless the web server is a private web development server), compilers, and other utilities that are not part of the web server suite or the basic operating system.

Check the directory structure of the server and verify that additional, unintended, or unneeded applications are not loaded on the system.

If, after review of the application on the system, there is no justification for the identified software, this is a finding."
  desc 'fix', 'Remove any unnecessary applications.'
  impact 0.7
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15533r277466_chk'
  tag severity: 'high'
  tag gid: 'V-214321'
  tag rid: 'SV-214321r879587_rule'
  tag stig_id: 'AS24-W1-000270'
  tag gtitle: 'SRG-APP-000141-WSR-000077'
  tag fix_id: 'F-15531r277467_fix'
  tag satisfies: ['SRG-APP-000141-WSR-000077', 'SRG-APP-000141-WSR-000080']
  tag 'documentable'
  tag legacy: ['SV-102463', 'V-92375']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
