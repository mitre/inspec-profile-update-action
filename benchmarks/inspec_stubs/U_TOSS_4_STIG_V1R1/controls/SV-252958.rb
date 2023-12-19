control 'SV-252958' do
  title 'TOSS must require users to reauthenticate for privilege escalation.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.'
  desc 'check', 'Verify that "/etc/sudoers" has no occurrences of "!authenticate."

Check that the "/etc/sudoers" file has no occurrences of "!authenticate" by running the following command:

$ sudo grep -i authenticate /etc/sudoers /etc/sudoers.d/*

If any occurrences of "!authenticate" return from the command, this is a finding.'
  desc 'fix', 'Remove any occurrence of "!authenticate" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56411r824196_chk'
  tag severity: 'medium'
  tag gid: 'V-252958'
  tag rid: 'SV-252958r824198_rule'
  tag stig_id: 'TOSS-04-020180'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-56361r824197_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
