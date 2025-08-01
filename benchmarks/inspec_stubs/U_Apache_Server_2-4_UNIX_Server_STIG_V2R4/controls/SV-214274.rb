control 'SV-214274' do
  title 'The Apache web server htpasswd files (if present) must reflect proper ownership and permissions.'
  desc 'In addition to OS restrictions, access rights to files and directories can be set on a website using the web server software. That is, in addition to allowing or denying all access rights, a rule can be specified that allows or denies partial access rights. For example, users can be given read-only access rights to files to view the information but not change the files.

This check verifies that the htpasswd file is only accessible by System Administrators (SAs) or Web Managers, with the account running the web service having group permissions of read and execute. "htpasswd" is a utility used by Netscape and Apache to provide for password access to designated websites.'
  desc 'check', 'Locate the htpasswd file by entering the following command:

find / -name htpasswd

Navigate to that directory.

Run: ls -l htpasswd

Permissions should be: r-x r - x - - - (550)

If permissions on "htpasswd" are greater than "550", this is a finding.

Verify the owner is the SA or Web Manager account.

If another account has access to this file, this is a finding.'
  desc 'fix', 'Ensure the SA or Web Manager account owns the "htpasswd" file.

Ensure permissions are set to "550".'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15488r277082_chk'
  tag severity: 'medium'
  tag gid: 'V-214274'
  tag rid: 'SV-214274r879887_rule'
  tag stig_id: 'AS24-U1-000970'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15486r277083_fix'
  tag 'documentable'
  tag legacy: ['V-92757', 'SV-102845']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
