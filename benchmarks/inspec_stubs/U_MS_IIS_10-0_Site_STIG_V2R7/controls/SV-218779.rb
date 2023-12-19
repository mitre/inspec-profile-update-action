control 'SV-218779' do
  title 'Interactive scripts on the IIS 10.0 web server must be located in unique and designated folders.'
  desc 'CGI and ASP scripts represent one of the most common and exploitable means of compromising a web server. All CGI and ASP program files must be segregated into their own unique folder to simplify the protection of these files. ASP scripts must be placed into a unique folder only containing other ASP scripts. JAVA and other technology-specific scripts must also be placed into their own unique folders. The placement of CGI, ASP, or equivalent scripts to special folders gives the Web Manager or the System Administrator (SA) control over what goes into those folders and to facilitate access control at the folder level.'
  desc 'check', 'Determine whether scripts are used on the web server for the target website. Common file extensions include, but are not limited to: .cgi, .pl, .vbs, .class, .c, .php, and .asp. 

All interactive programs must be placed in unique designated folders based on CGI or ASP script type. For modular and/or third-party applications, it is permissible to have script files in multiple folders.

Open the IIS 10.0 Manager.

Right-click the IIS 10.0 web site name and select "Explore".

Search for the listed script extensions. Each script type must be in its unique designated folder.

If scripts are not segregated from web content and in their own unique folders, this is a finding.'
  desc 'fix', 'All interactive programs must be placed in unique designated folders based on CGI or ASP script type.

Open the IIS 10.0 Manager.

Right-click the IIS 10.0 web server name and select "Explore".

Search for the listed script extensions.

Move each script type to its unique designated folder.

Set the permissions to the scripts folders as follows:

Administrators: FULL
TrustedInstaller: FULL
SYSTEM: FULL
ApplicationPoolId:READ
Custom Service Account: READ
Users: READ 
ALL APPLICATION PACKAGES: READ'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20252r311235_chk'
  tag severity: 'medium'
  tag gid: 'V-218779'
  tag rid: 'SV-218779r558649_rule'
  tag stig_id: 'IIST-SI-000261'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag fix_id: 'F-20250r311236_fix'
  tag 'documentable'
  tag legacy: ['SV-109383', 'V-100279']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
