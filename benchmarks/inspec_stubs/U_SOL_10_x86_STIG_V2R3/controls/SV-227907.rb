control 'SV-227907' do
  title 'The SSH daemon must be configured for IP filtering.'
  desc 'The SSH daemon must be configured for IP filtering to provide a layered defense against connection attempts from unauthorized addresses.'
  desc 'check', "Check the TCP wrappers configuration files to determine if SSHD is configured to use TCP wrappers.

Procedure:
# egrep '^[^#:]*(ALL|sshd)' /etc/hosts.deny
# egrep '^[^#:]*(ALL|sshd)' /etc/hosts.allow

If neither of the hosts.deny or hosts.allow files exist, this is a finding.
If no entries are returned, the TCP wrappers are not configured for SSHD, this is a finding."
  desc 'fix', 'Add appropriate IP restrictions for SSH to the /etc/hosts.deny and/or /etc/hosts.allow files.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30069r490126_chk'
  tag severity: 'medium'
  tag gid: 'V-227907'
  tag rid: 'SV-227907r603266_rule'
  tag stig_id: 'GEN005540'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30057r490127_fix'
  tag 'documentable'
  tag legacy: ['V-12022', 'SV-40279']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
