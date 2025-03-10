control 'SV-80429' do
  title 'Trend Deep Security must notify ISSO and ISSM of failed security verification tests.'
  desc 'If personnel are not notified of failed security verification tests, they will not be able to take corrective action and the unsecure condition(s) will remain. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to applications performing security functions and the applications performing security function verification/testing.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure the ISSO and ISSM are notified of failed security verification tests.

From Administration >> User Management >> Users

Select the account associated with the ISSM or ISSO and double-click.

Under the Contact Information tab, verify the Contact Information is associated with account is complete and accurate.

If the account information is missing or incorrect, this is a finding.

Next, verify the "Receive Alert Email" check box is selected.

If the "Receive Alert Email" checkbox is not selected, this is finding.'
  desc 'fix', 'Configure the Trend Deep Security server to notify ISSO and ISSM of failed security verification tests.

Go to Administration >> User Management >> Users

Select the account associated with the ISSM or ISSO and double-click.

Under the “Contact Information” tab enter the users Contact Information.

Next, select the checkbox for “Receive Alert Emails”.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66587r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65939'
  tag rid: 'SV-80429r1_rule'
  tag stig_id: 'TMDS-00-000200'
  tag gtitle: 'SRG-APP-000275'
  tag fix_id: 'F-72015r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001294']
  tag nist: ['SI-6 c']
end
