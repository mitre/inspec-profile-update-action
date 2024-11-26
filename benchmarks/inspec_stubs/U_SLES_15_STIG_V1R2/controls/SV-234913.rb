control 'SV-234913' do
  title 'The SUSE operating system must audit all uses of the sudoers file and all files in the /etc/sudoers.d/ directory.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

'
  desc 'check', %q(Verify the operating system generates audit records when successful/unsuccessful attempts to access the "/etc/sudoers" file and files in the "/etc/sudoers.d/" directory.

Check that the file and directory is being audited by performing the following command:

> sudo auditctl -l | grep -w '/etc/sudoers'

-w /etc/sudoers -p wa -k privileged-actions
-w /etc/sudoers.d -p wa -k privileged-actions

If the commands do not return output that match the examples, this is a finding.

Notes:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate audit records when successful/unsuccessful attempts to access the "/etc/sudoers" file and files in the "/etc/sudoers.d/" directory.

Add or update the following rule in "/etc/audit/rules.d/audit.rules":

-w /etc/sudoers -p wa -k privileged-actions

-w /etc/sudoers.d -p wa -k privileged-actions

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38101r619008_chk'
  tag severity: 'medium'
  tag gid: 'V-234913'
  tag rid: 'SV-234913r622137_rule'
  tag stig_id: 'SLES-15-030140'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-38064r619009_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
