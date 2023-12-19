control 'SV-36478' do
  title 'The web server’s htpasswd files (if present) must reflect proper ownership and permissions'
  desc 'In addition to OS restrictions, access rights to files and directories can be set on a web site using the web server software.  That is, in addition to allowing or denying all access rights, a rule can be specified that allows or denies partial access rights.  For example, users can be given read-only access rights to files, to view the information but not change the files.

This check verifies that the htpasswd file is only accessible by system administrators or web managers, with the account running the web service having group permissions of read and execute.  htpasswd is a utility used by Netscape and Apache to provide for password access to designated web sites.  I'
  desc 'check', 'To locate the htpasswd file enter the following command:

Find / -name htpasswd
Permissions should be r-x r - x - - - (550)

If permissions on htpasswd are greater than 550, this is a finding.

Owner should be the SA or Web Manager account, if another account has access to this file, this is a finding.'
  desc 'fix', 'The SA or Web Manager account should own the htpasswd file and permissions should be set to 550.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-2672r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2255'
  tag rid: 'SV-36478r2_rule'
  tag stig_id: 'WG270 A22'
  tag gtitle: 'WG270'
  tag fix_id: 'F-6758r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
