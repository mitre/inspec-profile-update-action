control 'SV-32326' do
  title 'All interactive programs must have restrictive access controls.'
  desc 'CGI is a programming standard for interfacing external applications with information servers, such as HTTP or web servers. CGI, represented by all upper case letters, should not be confused with the .cgi file extension. The .cgi file extension does represent a CGI script, but CGI scripts may be written in a number of programming languages (e.g., PERL, C, PHP, and JavaScript), each having their own unique file extension.

The use of CGI scripts represent one of the most common and exploitable means of compromising a web server. By definition, CGI scripts are executable by the operating system of the host server. While access control is provided via the web service, the execution of CGI programs is not limited unless the SA or the Web Manager takes specific measures. CGI programs can access and alter data files, launch other programs, and use the network.'
  desc 'check', 'Determine whether scripts are used on the web server for the subject website. Common file extensions include, but are not limited to: .cgi, .pl, .vb, .class, .c, .php, .asp, and .aspx. If the web site does not utilize CGI, this finding is N/A.

All interactive programs must have restrictive permissions.
1. Open the IIS Manager.
2. Right-click on the Site name and select Explore.
3. Search for the listed script extensions.
4. Set the permissions to the CGI scripts as follows:
     Administrators: FULL
     TrustedInstaller: FULL
     SYSTEM: FULL
     ApplicationPoolId: READ
     Custom Service Account: READ
     Users: READ
If the permissions listed above are less restrictive, this is a finding.'
  desc 'fix', 'All interactive programs must have restrictive permissions.
1. Open the IIS Manager.
2. Right-click on the Site name and select Explore.
4. Search for the listed script extensions.
5. Set the permissions to the CGI scripts as follows:
     Administrators: FULL
     TrustedInstaller: FULL
     SYSTEM: FULL
     ApplicationPoolId: READ
     Custom Service Account: READ
     Users: READ'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32732r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2229'
  tag rid: 'SV-32326r2_rule'
  tag stig_id: 'WG410 IIS7'
  tag gtitle: 'WG410'
  tag fix_id: 'F-29058r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
