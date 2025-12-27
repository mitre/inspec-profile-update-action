control 'SV-234833' do
  title 'The SUSE operating system must prevent unauthorized users from accessing system error messages.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the SUSE operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the SUSE operating system prevents unauthorized users from accessing system error messages.

Check the "/var/log/messages" file permissions with the following command:

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
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38021r618768_chk'
  tag severity: 'medium'
  tag gid: 'V-234833'
  tag rid: 'SV-234833r622137_rule'
  tag stig_id: 'SLES-15-010350'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-37984r618769_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
