control 'SV-230271' do
  title 'RHEL 8 must require users to provide a password for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', 'Verify that "/etc/sudoers" has no occurrences of "NOPASSWD".

Check that the "/etc/sudoers" file has no occurrences of "NOPASSWD" by running the following command:

$ sudo grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

%admin ALL=(ALL) NOPASSWD: ALL

If any occurrences of "NOPASSWD" are returned from the command and have not been documented with the ISSO as an organizationally defined administrative group utilizing MFA, this is a finding.'
  desc 'fix', 'Remove any occurrence of "NOPASSWD" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32940r567559_chk'
  tag severity: 'medium'
  tag gid: 'V-230271'
  tag rid: 'SV-230271r627750_rule'
  tag stig_id: 'RHEL-08-010380'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-32915r567560_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
