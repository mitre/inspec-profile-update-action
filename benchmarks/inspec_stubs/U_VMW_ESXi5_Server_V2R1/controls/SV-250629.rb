control 'SV-250629' do
  title 'The system must not permit root logins using remote access programs, such as SSH.'
  desc 'Even though communications are encrypted, an additional layer of security may be gained by extending the policy of not logging directly on as root. In addition, logging in with a user-specific account preserves the audit trail.'
  desc 'check', 'For ESXi hosts that are not managed by a vCenter Server, this check is not applicable.

Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep PermitRootLogin /etc/ssh/sshd_config

If "PermitRootLogin" is set to "yes", this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'This step assumes that root access to the system is available via the vSphere Client/vCenter Server, local availability via the DCUI, or that remote systems are accessible at the remote site via touch labor by an authorized (root) user.
Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/sshd_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"PermitRootLogin no"

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54064r798884_chk'
  tag severity: 'medium'
  tag gid: 'V-250629'
  tag rid: 'SV-250629r798886_rule'
  tag stig_id: 'SRG-OS-000109-ESXI5'
  tag gtitle: 'SRG-OS-000109-VMM-000550'
  tag fix_id: 'F-54018r798885_fix'
  tag 'documentable'
  tag legacy: ['V-39391', 'SV-51249']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
