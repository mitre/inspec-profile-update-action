control 'SV-219185' do
  title 'The Ubuntu operating system must require users to re-authenticate for privilege escalation and changing roles.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When the Ubuntu operating system provides the capability to escalate a functional capability or change security roles, it is critical the user re-authenticate.

'
  desc 'check', %q(Verify that "/etc/sudoers" has no occurrences of "NOPASSWD" or "!authenticate".

Check that the "/etc/sudoers" file has no occurrences of "NOPASSWD" or "!authenticate" by running the following command:

# sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*

If any occurrences of "NOPASSWD" or "!authenticate" return from the command, this is a finding.)
  desc 'fix', 'Remove any occurrence of "NOPASSWD" or "!authenticate" found in "/etc/sudoers" file or files in the /etc/sudoers.d directory.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20910r304883_chk'
  tag severity: 'medium'
  tag gid: 'V-219185'
  tag rid: 'SV-219185r853371_rule'
  tag stig_id: 'UBTU-18-010114'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-20909r304884_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157']
  tag 'documentable'
  tag legacy: ['SV-109701', 'V-100597']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
