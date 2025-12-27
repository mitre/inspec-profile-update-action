control 'SV-214494' do
  title 'Interactive scripts on the IIS 8.5 web server must have restrictive access controls.'
  desc 'CGI is a programming standard for interfacing external applications with information servers, such as HTTP or web servers. CGI, represented by all upper case letters, should not be confused with the .cgi file extension. The .cgi file extension does represent a CGI script, but CGI scripts may be written in a number of programming languages (e.g., PERL, C, PHP, and JavaScript), each having their own unique file extension.

The use of CGI scripts represent one of the most common and exploitable means of compromising a web server. By definition, CGI scripts are executable by the operating system of the host server. While access control is provided via the web service, the execution of CGI programs is not limited unless the SA or the Web Manager takes specific measures. CGI programs can access and alter data files, launch other programs, and use the network.'
  desc 'check', 'Determine whether scripts are used on the web server for the subject website. Common file extensions include, but are not limited to: .cgi, .pl, .vb, .class, .c, .php, .asp, and .aspx.

If the website does not utilize CGI, this finding is Not Applicable.

All interactive programs must have restrictive permissions.

Open the IIS 8.5 Manager.

Right-click the IIS 8.5 web site name and select “Explore”.

Search for the listed script extensions.

Review the permissions to the CGI scripts and verify only the permissions listed, or more restrictive permissions are assigned.

Administrators: FULL
Web Administrators: FULL
TrustedInstaller: FULL
ALL APPLICATION PACKAGES: Read
SYSTEM: FULL
ApplicationPoolId: READ
Custom Service Account: READ
Users: READ

If the permissions are less restrictive than listed above, this is a finding.'
  desc 'fix', 'Determine whether scripts are used on the web server for the subject website. Common file extensions include, but are not limited to: .cgi, .pl, .vb, .class, .c, .php, .asp, and .aspx.

If the website does not utilize CGI, this finding is NA.

All interactive programs must have restrictive permissions.

Open the IIS 8.5 Manager.

Right-click the IIS 8.5 web server name and select “Explore”.

Search for the listed script extensions.

Set the permissions to the CGI scripts as follows:

Administrators: FULL
Web Administrators: FULL
TrustedInstaller: FULL
ALL APPLICATION PACKAGES: Read
SYSTEM: FULL
ApplicationPoolId: READ
Custom Service Account: READ
Users: READ'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15703r505342_chk'
  tag severity: 'medium'
  tag gid: 'V-214494'
  tag rid: 'SV-214494r879587_rule'
  tag stig_id: 'IISW-SI-000262'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag fix_id: 'F-15701r505343_fix'
  tag 'documentable'
  tag legacy: ['SV-91583', 'V-76887']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
