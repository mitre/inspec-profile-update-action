control 'SV-32327' do
  title 'All interactive programs must be placed in unique designated folders.'
  desc 'CGI & ASP scripts represent one of the most common and exploitable means of compromising a web server.  All CGI & ASP program files must be segregated into their own unique folder to simplify the protection of these files. ASP scripts must be placed into a unique folder only containing other ASP scripts. JAVA and other technology-specific scripts must also be placed into their own unique folders. The placement of CGI, ASP, or equivalent scripts to special folders gives the Web Manager or the SA control over what goes into those folders and to facilitate access control at the folder level.'
  desc 'check', 'Determine whether scripts are used on the web server for the target website. Common file extensions include, but are not limited to: .cgi, .pl, .vb, .class, .c, .php, .asp, and .aspx.  If the web site does not utilize CGI or ASP, this finding is N/A.

All interactive programs must be placed in unique designated folders based on CGI or ASP script type.

1. Open the IIS Manager.
2. Right-click on the Site name and select Explore.
3. Search for the listed script extensions.
4. Each script type must be in its unique designated folder. If scripts are not segregated from web content and in their own unique folders, then this is a finding.'
  desc 'fix', 'All interactive programs must be placed in unique designated folders based on CGI or ASP script type.

1. Open the IIS Manager.
2. Right-click on the Site name and select Explore.
3. Search for the listed script extensions.
4. Move each script type to its unique designated folder.
5. Set the permissions to the scripts folders as follows:
     Administrators: FULL
     TrustedInstaller: FULL
     SYSTEM: FULL
     ApplicationPoolId: READ
     Custom Service Account: READ
     Users: READ'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32733r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2228'
  tag rid: 'SV-32327r2_rule'
  tag stig_id: 'WG400 IIS7'
  tag gtitle: 'WG400'
  tag fix_id: 'F-29057r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
