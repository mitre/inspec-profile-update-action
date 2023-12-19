control 'SV-237643' do
  title 'RHEL 8 must require re-authentication when using the "sudo" command.'
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
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-40862r646897_chk'
  tag severity: 'medium'
  tag gid: 'V-237643'
  tag rid: 'SV-237643r646899_rule'
  tag stig_id: 'RHEL-08-010384'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-40825r646898_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
