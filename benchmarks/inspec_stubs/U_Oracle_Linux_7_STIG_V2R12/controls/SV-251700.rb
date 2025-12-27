control 'SV-251700' do
  title 'The Oracle Linux operating system must not be configured to bypass password requirements for privilege escalation.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.

'
  desc 'check', 'Verify the operating system is not be configured to bypass password requirements for privilege escalation.

Check the configuration of the "/etc/pam.d/sudo" file with the following command:

$ sudo grep pam_succeed_if /etc/pam.d/sudo

If any occurrences of "pam_succeed_if" is returned from the command, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to supply a password for privilege escalation.

Check the configuration of the "/etc/ pam.d/sudo" file with the following command:
$ sudo vi /etc/pam.d/sudo

Remove any occurrences of "pam_succeed_if" in the file.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-55137r809178_chk'
  tag severity: 'medium'
  tag gid: 'V-251700'
  tag rid: 'SV-251700r853742_rule'
  tag stig_id: 'OL07-00-010344'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-55091r853741_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
