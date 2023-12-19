control 'SV-238208' do
  title 'The Ubuntu operating system must require users to reauthenticate for privilege escalation or when changing roles.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.  
 
When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', %q(Verify the "/etc/sudoers" file has no occurrences of "NOPASSWD" or "!authenticate" by running the following command: 
 
$ sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/* 
 
If any occurrences of "NOPASSWD" or "!authenticate" return from the command, this is a finding.)
  desc 'fix', 'Remove any occurrence of "NOPASSWD" or "!authenticate" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41418r653797_chk'
  tag severity: 'medium'
  tag gid: 'V-238208'
  tag rid: 'SV-238208r653799_rule'
  tag stig_id: 'UBTU-20-010014'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-41377r653798_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
