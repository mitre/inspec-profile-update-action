control 'SV-221810' do
  title 'The Oracle Linux operating system must audit all uses of the sudoers file and all files in the /etc/sudoers.d/ directory.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to access the "/etc/sudoers" file and files in the "/etc/sudoers.d/" directory. 

Check for modification of the following files being audited by performing the following commands to check the file system rules in "/etc/audit/audit.rules": 

# grep -i "/etc/sudoers" /etc/audit/audit.rules

-w /etc/sudoers -p wa -k privileged-actions

# grep -i "/etc/sudoers.d/" /etc/audit/audit.rules

-w /etc/sudoers.d/ -p wa -k privileged-actions

If the commands do not return output that match the examples, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to access the "/etc/sudoers" file and files in the "/etc/sudoers.d/" directory.

Add or update the following rule in "/etc/audit/rules.d/audit.rules":

-w /etc/sudoers -p wa -k privileged-actions

-w /etc/sudoers.d/ -p wa -k privileged-actions

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23525r419502_chk'
  tag severity: 'medium'
  tag gid: 'V-221810'
  tag rid: 'SV-221810r603260_rule'
  tag stig_id: 'OL07-00-030700'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-23514r419503_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['SV-108463', 'V-99359']
  tag cci: ['CCI-000130', 'CCI-000172']
  tag nist: ['AU-3 a', 'AU-12 c']
end
