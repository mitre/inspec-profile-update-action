control 'SV-217198' do
  title 'The SUSE operating system audit event multiplexor must be configured to use Kerberos.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Allowing devices and users to connect to or from the system without first authenticating them allows untrusted access and can lead to a compromise or attack. Audit events may include sensitive data must be encrypted prior to transmission. Kerberos provides a mechanism to provide both authentication and encryption for audit event records.'
  desc 'check', 'Determine if the SUSE operating system audit event multiplexor is configured to use Kerberos by running the following command:

# sudo cat /etc/audisp/audisp-remote.conf | grep enable_krb5
enable_krb5 = yes

If "enable-krb5" is not set to "yes", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system audit event multiplexor to use Kerberos by editing the "/etc/audisp/audisp-remote.conf" file. 

Edit or add the following line to match the text below:

enable_krb5 = yes'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18426r369750_chk'
  tag severity: 'low'
  tag gid: 'V-217198'
  tag rid: 'SV-217198r877390_rule'
  tag stig_id: 'SLES-12-020080'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-18424r369751_fix'
  tag 'documentable'
  tag legacy: ['V-77303', 'SV-91999']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
