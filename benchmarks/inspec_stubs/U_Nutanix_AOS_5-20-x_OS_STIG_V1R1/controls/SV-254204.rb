control 'SV-254204' do
  title 'Nutanix AOS must require users to reauthenticate for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', 'Confirm Nutanix AOS is configured as shown for reauthentication in the sudoers file.

$ grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

If any occurrences of "NOPASSWD" are returned from the command and have not been documented with the Information System Security Officer (ISSO) as an organizationally defined administrative group utilizing MFA, this is a finding.'
  desc 'fix', 'If any occurrences of "NOPASSWD" found are not documented with the ISSO need to be removed. Configure Nutanix AOS to meet this requirement run the following command:

salt-call state.sls security/CVM/manualCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57689r846698_chk'
  tag severity: 'medium'
  tag gid: 'V-254204'
  tag rid: 'SV-254204r846700_rule'
  tag stig_id: 'NUTX-OS-001170'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-57640r846699_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
