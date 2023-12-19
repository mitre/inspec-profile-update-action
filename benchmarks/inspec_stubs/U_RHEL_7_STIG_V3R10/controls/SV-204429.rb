control 'SV-204429' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that users must provide a password for privilege escalation.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.

'
  desc 'check', 'Verify the operating system requires users to supply a password for privilege escalation.

Check the configuration of the "/etc/sudoers" and "/etc/sudoers.d/*" files with the following command:

$ sudo grep -ir nopasswd /etc/sudoers /etc/sudoers.d

If any occurrences of "NOPASSWD" are returned from the command and have not been documented with the Information System Security Officer (ISSO) as an organizationally defined administrative group utilizing MFA, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to supply a password for privilege escalation.

Check the configuration of the "/etc/sudoers" file with the following command:
$ sudo visudo

Remove any occurrences of "NOPASSWD" tags in the file.

Check the configuration of the /etc/sudoers.d/* files with the following command:
$ sudo grep -ir nopasswd /etc/sudoers.d

Remove any occurrences of "NOPASSWD" tags in the file.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-36340r861001_chk'
  tag severity: 'medium'
  tag gid: 'V-204429'
  tag rid: 'SV-204429r861003_rule'
  tag stig_id: 'RHEL-07-010340'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-36303r861002_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag legacy: ['V-71947', 'SV-86571']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
