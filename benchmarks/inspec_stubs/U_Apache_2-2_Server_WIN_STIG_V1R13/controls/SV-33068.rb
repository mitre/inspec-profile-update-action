control 'SV-33068' do
  title 'The web server must use a vendor-supported version of the web server software.'
  desc 'Many vulnerabilities are associated with old versions of web server software. As hot fixes and patches are issued, these solutions are included in the next version of the server software.  Maintaining the web server at a current version makes the efforts of a malicious user to exploit the web service more difficult.'
  desc 'check', 'Determine the version of the Apache software that is running on the system. 

Use the command line interface and navigate to the directory where Apache httpd Server is installed. From the command line type the following command: httpd.exe –v. Press Enter. This will display the version of apache installed on the system.

Note: There are other ways, too, of determining the version of Apache (in the service itself and Add/Remove programs).

If the version of Apache is not at the following version or higher, this is a finding.

Apache httpd server version 2.2 - Release 2.2.31 (July 2015)'
  desc 'fix', 'Upgrade software to a supported version.'
  impact 0.7
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33738r2_chk'
  tag severity: 'high'
  tag gid: 'V-2246'
  tag rid: 'SV-33068r2_rule'
  tag stig_id: 'WG190 W22'
  tag gtitle: 'WG190'
  tag fix_id: 'F-29373r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
