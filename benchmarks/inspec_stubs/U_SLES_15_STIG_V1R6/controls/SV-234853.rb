control 'SV-234853' do
  title 'The SUSE operating system must reauthenticate users when changing authenticators, roles, or escalating privileges.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization. 

When the SUSE operating system provides the capability to change user authenticators, change security roles, or escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', %q(Verify that the SUSE operating system requires reauthentication when changing authenticators, roles, or escalating privileges.

Check that "/etc/sudoers" has no occurrences of "NOPASSWD" or "!authenticate" with the following command:

> sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers

If any uncommented lines containing "!authenticate", or "NOPASSWD" are returned and active accounts on the system have valid passwords, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to remove any occurrence of "NOPASSWD" or "!authenticate" found in the "/etc/sudoers" file. If the system does not use passwords for authentication, the "NOPASSWD" tag may exist in the file.'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38041r618828_chk'
  tag severity: 'high'
  tag gid: 'V-234853'
  tag rid: 'SV-234853r622137_rule'
  tag stig_id: 'SLES-15-010450'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-38004r618829_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
