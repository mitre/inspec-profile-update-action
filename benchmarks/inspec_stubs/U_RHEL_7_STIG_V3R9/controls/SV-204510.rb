control 'SV-204510' do
  title 'The Red Hat Enterprise Linux operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

'
  desc 'check', 'Verify the operating system encrypts audit records off-loaded onto a different system or media from the system being audited.

To determine if the transfer is encrypted, use the following command:

# grep -i enable_krb5 /etc/audisp/audisp-remote.conf
enable_krb5 = yes

If the value of the "enable_krb5" option is not set to "yes" or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media. 

If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding.'
  desc 'fix', 'Configure the operating system to encrypt the transfer of off-loaded audit records onto a different system or media from the system being audited.

Uncomment the "enable_krb5" option in "/etc/audisp/audisp-remote.conf" and set it with the following line:

enable_krb5 = yes'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4634r88722_chk'
  tag severity: 'medium'
  tag gid: 'V-204510'
  tag rid: 'SV-204510r853908_rule'
  tag stig_id: 'RHEL-07-030310'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-4634r88723_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag legacy: ['V-72085', 'SV-86709']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
