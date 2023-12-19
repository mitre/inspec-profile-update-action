control 'SV-221692' do
  title 'The Oracle Linux operating system must be configured so that users must provide a password for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which authorization has not been granted. 

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', 'Verify the operating system requires users to supply a password for privilege escalation.

Check the configuration of the "/etc/sudoers" and "/etc/sudoers.d/*" files with the following command:

# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

If any occurrences of "NOPASSWD" are returned from the command and have not been documented with the Information System Security Officer (ISSO) as an organizationally defined administrative group utilizing MFA, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to supply a password for privilege escalation.

Check the configuration of the "/etc/sudoers" file with the following command:
# visudo

Remove any occurrences of "NOPASSWD" tags in the file.

Check the configuration of the /etc/sudoers.d/* files with the following command:
# grep -i nopasswd /etc/sudoers.d/*

Remove any occurrences of "NOPASSWD" tags in the file.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36269r602401_chk'
  tag severity: 'medium'
  tag gid: 'V-221692'
  tag rid: 'SV-221692r603260_rule'
  tag stig_id: 'OL07-00-010340'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-36233r602402_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag legacy: ['V-99123', 'SV-108227']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
