control 'SV-252931' do
  title 'TOSS must require re-authentication when using the "sudo" command.'
  desc %q(Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to escalate a functional capability, it is critical the organization requires the user to re-authenticate when using the "sudo" command.

If the value is set to an integer less than 0, the user's time stamp will not expire and the user will not have to re-authenticate for privileged actions until the user's session is terminated.)
  desc 'check', %q(Verify the operating system requires re-authentication when using the "sudo" command to elevate privileges.

$ sudo egrep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d
/etc/sudoers:Defaults timestamp_timeout=0

If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a finding.)
  desc 'fix', 'Configure the "sudo" command to require re-authentication.

Edit the /etc/sudoers file:
$ sudo visudo

Add or modify the following line:
Defaults timestamp_timeout=0'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56384r824115_chk'
  tag severity: 'medium'
  tag gid: 'V-252931'
  tag rid: 'SV-252931r824117_rule'
  tag stig_id: 'TOSS-04-010230'
  tag gtitle: 'SRG-OS-000373-GPOS-00158'
  tag fix_id: 'F-56334r824116_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
