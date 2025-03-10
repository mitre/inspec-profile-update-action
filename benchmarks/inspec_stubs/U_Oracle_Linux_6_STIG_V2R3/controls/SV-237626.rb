control 'SV-237626' do
  title 'The Oracle Linux operating system must require re-authentication when using the "sudo" command.'
  desc %q(Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 
When operating systems provide the capability to escalate a functional capability, it is critical the organization requires the user to re-authenticate when using the "sudo" command.
If the value is set to an integer less than 0, the user's time stamp will not expire and the user will not have to re-authenticate for privileged actions until the user's session is terminated.)
  desc 'check', %q(Verify the operating system requires re-authentication when using the "sudo" command to elevate privileges.

$ sudo grep -i 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/*
/etc/sudoers:Defaults timestamp_timout=0

If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a finding.)
  desc 'fix', 'Configure the "sudo" command to require re-authentication.
Edit the /etc/sudoers file:
$ sudo visudo

Add or modify the following line:
Defaults timestamp_timeout=[value]
Note: The "[value]" must be a number that is greater than or equal to "0".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-40845r646947_chk'
  tag severity: 'medium'
  tag gid: 'V-237626'
  tag rid: 'SV-237626r646949_rule'
  tag stig_id: 'OL6-00-000537'
  tag gtitle: 'SRG-OS-000373'
  tag fix_id: 'F-40808r646948_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
