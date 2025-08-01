control 'SV-204430' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that users must re-authenticate for privilege escalation.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', 'Verify the operating system requires users to reauthenticate for privilege escalation.

Check the configuration of the "/etc/sudoers" and "/etc/sudoers.d/*" files with the following command:

# grep -i authenticate /etc/sudoers /etc/sudoers.d/*

If any uncommented line is found with a "!authenticate" tag, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to reauthenticate for privilege escalation.

Check the configuration of the "/etc/sudoers" file with the following command:

# visudo
Remove any occurrences of "!authenticate" tags in the file.

Check the configuration of the "/etc/sudoers.d/*" files with the following command:

# grep -i authenticate /etc/sudoers /etc/sudoers.d/*
Remove any occurrences of "!authenticate" tags in the file(s).'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4554r88482_chk'
  tag severity: 'medium'
  tag gid: 'V-204430'
  tag rid: 'SV-204430r853885_rule'
  tag stig_id: 'RHEL-07-010350'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-4554r88483_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag legacy: ['V-71949', 'SV-86573']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
