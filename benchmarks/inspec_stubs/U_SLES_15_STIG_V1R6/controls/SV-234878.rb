control 'SV-234878' do
  title 'The SUSE operating system must require re-authentication when using the "sudo" command.'
  desc %q(Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to escalate a functional capability, it is critical the organization requires the user to re-authenticate when using the "sudo" command.

If the value is set to an integer less than 0, the user's time stamp will not expire and the user will not have to re-authenticate for privileged actions until the user's session is terminated.)
  desc 'check', %q(Verify the operating system requires re-authentication when using the "sudo" command to elevate privileges.

> sudo grep -i 'timestamp_timeout'

/etc/sudoers /etc/sudoers.d/*
/etc/sudoers:Defaults timestamp_timeout=0

If results are returned from more than one file location, this is a finding.

If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a finding.)
  desc 'fix', 'Configure the "sudo" command to require re-authentication.
Edit the /etc/sudoers file:

> sudo visudo

Add or modify the following line:
Defaults timestamp_timeout=[value]
Note: The "[value]" must be a number that is greater than or equal to "0".'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38066r809457_chk'
  tag severity: 'medium'
  tag gid: 'V-234878'
  tag rid: 'SV-234878r809458_rule'
  tag stig_id: 'SLES-15-020102'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-38029r618904_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
