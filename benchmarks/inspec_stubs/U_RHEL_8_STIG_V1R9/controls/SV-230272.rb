control 'SV-230272' do
  title 'RHEL 8 must require users to reauthenticate for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', 'Verify that "/etc/sudoers" has no occurrences of "!authenticate".

Check that the "/etc/sudoers" file has no occurrences of "!authenticate" by running the following command:

$ sudo grep -i !authenticate /etc/sudoers /etc/sudoers.d/*

If any occurrences of "!authenticate" return from the command, this is a finding.'
  desc 'fix', 'Remove any occurrence of "!authenticate" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32941r567562_chk'
  tag severity: 'medium'
  tag gid: 'V-230272'
  tag rid: 'SV-230272r854027_rule'
  tag stig_id: 'RHEL-08-010381'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-32916r567563_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
