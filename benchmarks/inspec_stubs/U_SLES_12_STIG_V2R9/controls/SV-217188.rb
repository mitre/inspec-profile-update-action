control 'SV-217188' do
  title 'The SUSE operating system must prevent unauthorized users from accessing system error messages.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the SUSE operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that the SUSE operating system prevents unauthorized users from accessing system error messages.

Check the "/var/log/messages" file permissions with the following comand:

> sudo stat -c "%n %U:%G %a" /var/log/messages

/var/log/messages root:root 640

Check that "permissions.local" file contains the correct permissions rules with the following command:

> grep -i messages /etc/permissions.local

/var/log/messages root:root 640

If the effective permissions do not match the "permissions.local" file, the command does not return any output, or is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to prevent unauthorized users from accessing system error messages.

Add or update the following rules in "/etc/permissions.local":

/var/log/messages root:root 640

Set the correct permissions with the following command:

> sudo chkstat --set --system'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18416r646732_chk'
  tag severity: 'medium'
  tag gid: 'V-217188'
  tag rid: 'SV-217188r646734_rule'
  tag stig_id: 'SLES-12-010890'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-18414r646733_fix'
  tag 'documentable'
  tag legacy: ['SV-91971', 'V-77275']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
