control 'SV-250311' do
  title 'The Oracle Linux operating system must elevate the SELinux context when an administrator calls the sudo command.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Verify the operating system elevates the SELinux context when an administrator calls the sudo command with the following command:

This command must be ran as root:
# grep -r sysadm_r /etc/sudoers /etc/sudoers.d
%wheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

If conflicting results are returned, this is a finding.

If a designated sudoers administrator group or account(s) is not configured to elevate the SELinux type and role to "sysadm_t" and "sysadm_r" with the use of the sudo command, this is a finding.'
  desc 'fix', 'Configure the operating system to elevate the SELinux context when an administrator calls the sudo command.
Edit a file in the /etc/sudoers.d directory with the following command:
$ sudo visudo -f /etc/sudoers.d/<customfile>

Use the following example to build the <customfile> in the /etc/sudoers.d directory to allow any administrator belonging to a designated sudoers admin group to elevate their SELinux context with the use of the sudo command:
%wheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

Remove any configurations that conflict with the above from the following locations: 
/etc/sudoers
/etc/sudoers.d/'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-53745r858467_chk'
  tag severity: 'medium'
  tag gid: 'V-250311'
  tag rid: 'SV-250311r860888_rule'
  tag stig_id: 'OL07-00-020023'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-53699r858468_fix'
  tag 'documentable'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
end
