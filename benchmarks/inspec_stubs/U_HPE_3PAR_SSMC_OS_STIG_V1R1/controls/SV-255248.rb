control 'SV-255248' do
  title 'SSMC must prevent nonprivileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Nonprivileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from nonprivileged users.

'
  desc 'check', 'Verify that SSMC prevents nonprivileged users from executing privileged functions by doing the following:

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following commands:

$ sudo /ssmc/bin/config_security.sh -o sudo_password -a status

Sudo password is enabled

If the command output does not read "Sudo password is enabled", this is a finding.'
  desc 'fix', 'Configure SSMC to prevent nonprivileged users from executing privileged functions by doing the following:

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following command:

$ sudo /ssmc/bin/config_security.sh -o sudo_password -a enable'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58861r869892_chk'
  tag severity: 'medium'
  tag gid: 'V-255248'
  tag rid: 'SV-255248r869894_rule'
  tag stig_id: 'SSMC-OS-020080'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-58805r869893_fix'
  tag satisfies: ['SRG-OS-000324-GPOS-00125', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-002235']
  tag nist: ['IA-11', 'AC-6 (10)']
end
