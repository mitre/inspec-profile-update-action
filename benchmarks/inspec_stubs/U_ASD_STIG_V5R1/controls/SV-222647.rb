control 'SV-222647' do
  title 'Test procedures must be created and at least annually executed to ensure system initialization, shutdown, and aborts are configured to verify the system remains in a secure state.'
  desc 'Secure state assurance cannot be accomplished without testing the system state at least annually to ensure the system remains in a secure state upon initialization, shutdown, and aborts.'
  desc 'check', 'Review the process documentation and interview the admin staff.

Identify if testing procedures exist and if they include annual testing to ensure the application remains in a secure state on initialization, shutdown, and aborts.

Checks should include at a minimum, attempts to access the application and application configuration settings without credentials or with improper credentials both locally and remotely.

Dates should be noted as to the last date of testing.

If annual testing procedures do not exist, or if administrators are unable to provide testing dates that indicate the tests were conducted within the last year, this is a finding.'
  desc 'fix', 'Create test procedures to test the security state of the application and exercise test procedures annually.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24317r493849_chk'
  tag severity: 'low'
  tag gid: 'V-222647'
  tag rid: 'SV-222647r508029_rule'
  tag stig_id: 'APSC-DV-003160'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24306r493850_fix'
  tag 'documentable'
  tag legacy: ['SV-84995', 'V-70373']
  tag cci: ['CCI-003182', 'CCI-000366']
  tag nist: ['SA-11 (2)', 'CM-6 b']
end
