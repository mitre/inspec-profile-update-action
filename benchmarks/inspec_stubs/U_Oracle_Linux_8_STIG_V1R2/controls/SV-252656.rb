control 'SV-252656' do
  title 'The OL 8 operating system must not be configured to bypass password requirements for privilege escalation.'
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

Remove any occurrences of " pam_succeed_if " in the file.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-56112r818762_chk'
  tag severity: 'medium'
  tag gid: 'V-252656'
  tag rid: 'SV-252656r818764_rule'
  tag stig_id: 'OL08-00-010385'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-56062r818763_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
