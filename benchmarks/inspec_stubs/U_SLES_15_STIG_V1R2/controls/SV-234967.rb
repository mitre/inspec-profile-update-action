control 'SV-234967' do
  title 'The SUSE operating system audit event multiplexor must be configured to use Kerberos.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Allowing devices and users to connect to or from the system without first authenticating them allows untrusted access and can lead to a compromise or attack. Audit events that may include sensitive data must be encrypted prior to transmission. Kerberos provides a mechanism to provide both authentication and encryption for audit event records.'
  desc 'check', 'Determine if the SUSE operating system audit event multiplexor is configured to use Kerberos by running the following command:

> sudo grep enable_krb5 /etc/audisp/audisp-remote.conf
enable_krb5 = yes

If "enable_krb5" is not set to "yes", or is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system audit event multiplexor to use Kerberos by editing the "/etc/audisp/audisp-remote.conf" file. 

Edit or add the following line to match the text below:

enable_krb5 = yes'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38155r619170_chk'
  tag severity: 'low'
  tag gid: 'V-234967'
  tag rid: 'SV-234967r622137_rule'
  tag stig_id: 'SLES-15-030680'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-38118r619171_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
