control 'SV-221453' do
  title 'The OHS htpasswd files (if present) must reflect proper ownership and permissions.'
  desc 'In addition to OS restrictions, access rights to files and directories can be set on a web site using the web server software.  That is, in addition to allowing or denying all access rights, a rule can be specified that allows or denies partial access rights.  For example, users can be given read-only access rights to files, to view the information but not change the files.

This check verifies that the htpasswd file is only accessible by system administrators or web managers, with the account running the web service having group permissions of read and execute.  Htpasswd is a utility used by OHS to provide for password access to designated web sites.'
  desc 'check', '1. Check the permissions of the htpasswd file. (e.g., ls -l $ORACLE_HOME/ohs/bin/htpasswd).

2. If the file has permissions beyond "-rwxr-----" (i.e., 740), this is a finding.'
  desc 'fix', 'Set permissions on htpasswd to 740 (i.e., chmod 740 $ORACLE_HOME/ohs/bin/htpasswd).'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23168r415042_chk'
  tag severity: 'medium'
  tag gid: 'V-221453'
  tag rid: 'SV-221453r879887_rule'
  tag stig_id: 'OH12-1X-000216'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23157r415043_fix'
  tag 'documentable'
  tag legacy: ['SV-79159', 'V-64669']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
