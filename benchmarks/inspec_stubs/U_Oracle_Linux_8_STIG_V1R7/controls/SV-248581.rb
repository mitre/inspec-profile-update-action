control 'SV-248581' do
  title 'OL 8 must require users to provide a password for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', 'Verify that "/etc/sudoers" has no occurrences of "NOPASSWD".

Check that the "/etc/sudoers" file has no occurrences of "NOPASSWD" by running the following command:

$ sudo grep -ir nopasswd /etc/sudoers /etc/sudoers.d

%admin ALL=(ALL) NOPASSWD: ALL

If any occurrences of "NOPASSWD" are returned from the command and have not been documented with the ISSO as an organizationally defined administrative group using MFA, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to supply a password for privilege escalation.

Check the configuration of the "/etc/sudoers" file with the following command:
$ sudo visudo

Remove any occurrences of "NOPASSWD" tags in the file.

Check the configuration of the /etc/sudoers.d/* files with the following command:
$ sudo grep -ir nopasswd /etc/sudoers.d

Remove any occurrences of "NOPASSWD" tags in the file.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52015r860913_chk'
  tag severity: 'medium'
  tag gid: 'V-248581'
  tag rid: 'SV-248581r860915_rule'
  tag stig_id: 'OL08-00-010380'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-51969r860914_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
