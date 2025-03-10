control 'SV-248582' do
  title 'OL 8 must require users to reauthenticate for privilege escalation and changing roles.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', 'Verify that the "/etc/sudoers" file has no occurrences of "!authenticate" by running the following command:

$ sudo egrep -i !authenticate /etc/sudoers /etc/sudoers.d/*

If any occurrences of "!authenticate" return from the command, this is a finding.'
  desc 'fix', 'Remove any occurrence of "!authenticate" found in the "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52016r779310_chk'
  tag severity: 'medium'
  tag gid: 'V-248582'
  tag rid: 'SV-248582r853764_rule'
  tag stig_id: 'OL08-00-010381'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-51970r779311_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
