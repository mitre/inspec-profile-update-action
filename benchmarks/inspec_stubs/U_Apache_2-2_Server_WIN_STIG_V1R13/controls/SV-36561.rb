control 'SV-36561' do
  title 'The web server’s htpasswd files (if present) must reflect proper ownership and permissions.'
  desc 'In addition to OS restrictions, access rights to files and directories can be set on a web site using the web server software.  That is, in addition to allowing or denying all access rights, a rule can be specified that allows or denies partial access rights.  For example, users can be given read-only access rights to files, to view the information but not change the files.

This check verifies that the htpasswd file is only accessible by system administrators or web managers, with the account running the web service having group permissions of read and execute.  Htpasswd is a utility used by Netscape and Apache to provide for password access to designated web sites.  I'
  desc 'check', 'Search for the htpasswd.exe file. Right click the htpasswd file, if present. Select the Properties window, select the Security tab.

Examine the access rights for the file. The SA or Web Manager account should have Full Control, the account running the web service should have read and execute permissions. 

If entries other than Administrators, Web Manager account, or System are present, this is a finding.'
  desc 'fix', 'The SA or Web Manager account should have Full Control, the account running the web service should have read and execute permissions to the htpasswd file.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-35666r4_chk'
  tag severity: 'medium'
  tag gid: 'V-2255'
  tag rid: 'SV-36561r2_rule'
  tag stig_id: 'WG270 W22'
  tag gtitle: 'WG270'
  tag fix_id: 'F-30901r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
