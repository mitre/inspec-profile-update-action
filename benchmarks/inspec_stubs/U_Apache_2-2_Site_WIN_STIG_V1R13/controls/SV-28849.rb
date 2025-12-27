control 'SV-28849' do
  title 'Interactive scripts used on a web server must have proper access controls.'
  desc 'The use of CGI scripts represent one of the most common and exploitable means of compromising a web server. By definition, CGI scripts are executable by the operating system of the host server. While access control is provided via the web service, the execution of CGI programs is not limited unless the SA or the Web Manager takes specific measures. CGI programs can access and alter data files, launch other programs, and use the network. CGI programs can be written in any available programming language. C, PERL, PHP, Javascript, VBScript, and shell programs (e.g., sh, ksh, bash, etc.) are popular choices. 

CGI is a standard for interfacing external applications with information servers, such as HTTP or web servers. The definition of CGI as web-based applications is not to be confused with the more specific .cgi file extension. ASP, JSP, JAVA, and PERL scripts are commonly found in these circumstances.

Clarification:
This vulnerability, which is related to VMS vulnerability V-2228, requires that appropriate access permissions are applied to CGI files.'
  desc 'check', 'Query the SA to determine if CGI scripts are used as part of the web site. 

If interactive scripts are being used, check the permissions of these files to ensure they meet the following permissions:

interactive script files

Administrators Full Control
WebManagers Modify
System Read/Execute
Webserver Account Read/Execute 

If the interactive scripts do not meet the above permissions or are less restrictive, this is a finding.'
  desc 'fix', 'Ensure the CGI scripts are owned by root, the service account running the web service, the web author or the SA, and that the anonymous web user account has Read Only or Read - Execute permissions to such scripts.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-35739r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2229'
  tag rid: 'SV-28849r1_rule'
  tag stig_id: 'WG410 W22'
  tag gtitle: 'WG410'
  tag fix_id: 'F-30980r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
