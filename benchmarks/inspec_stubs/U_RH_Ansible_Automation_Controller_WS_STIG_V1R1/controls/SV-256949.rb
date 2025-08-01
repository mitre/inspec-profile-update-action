control 'SV-256949' do
  title 'All Automation Controller NGINX web servers must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.'
  desc "Controlling what a user of a hosted application can access is part of the security posture of the Automation Controller NGINX web server.

Any time a user can access more functionality than is needed for the operation of the hosted application, it  poses a security issue. A user with too much access can view information that is not needed for the user's job role, or the user could use the function in an unintentional manner.

A MIME tells the Automation Controller NGINX web servers what type of program various file types and extensions are and what external utilities or programs are needed to execute the file type.

A shell is a program that serves as the basic interface between the user and the operating system, so hosted application users must not have access to these programs. Shell programs may execute shell escapes and can then perform unauthorized activities that could damage the security posture of Automation Controller."
  desc 'check', %q(As a System Administrator for each Automation Controller NGINX web server, check the allowed mime types and associated shell applications:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' ` ; MIME_TYPES=`grep mime $NGINXCONF | awk '{printf $2}' | sed 's/;$//' ` ; disallowed_mime_types=('application.*\sbin' 'application.*\sexe' 'application.*\srpm' 'application.*\smsi' 'application.*\smsp application.*\smsm' 'application.*\sjs') ; echo "${disallowed_mime_types[*]}" | tr ' ' '\n' >tempfile ; cat $MIME_TYPES | grep -f tempfile 1>/dev/null && echo "FAILED"; rm -f tempfile

If "FAILED" is displayed, this is a finding.)
  desc 'fix', %q(As a System Administrator for each Automation Controller NGINX web server, remove the disallowed mime types:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' ` ; 
MIME_TYPES=`grep mime $NGINXCONF | awk '{printf $2}' | sed 's/;$//' ` ;
 disallowed_mime_types=('application.*\sbin' 'application.*\sexe' 'application.*\srpm' 'application.*\smsi' 'application.*\smsp application.*\smsm' 'application.*\sjs') ; 
echo "${disallowed_mime_types[*]}" | tr ' ' '\n' >tempfile ; cat $MIME_TYPES | grep -vf tempfile >$MIME_TYPES; rm -f tempfile

Restart NGINX.)
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60624r902359_chk'
  tag severity: 'medium'
  tag gid: 'V-256949'
  tag rid: 'SV-256949r902361_rule'
  tag stig_id: 'APWS-AT-000310'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag fix_id: 'F-60566r902360_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
