control 'SV-234982' do
  title 'The SUSE operating system must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify the SUSE operating system enforces a delay of at least four seconds between logon prompts following a failed logon attempt.

Check that the SUSE operating system enforces a delay of at least four seconds between logon prompts following a failed logon attempt with the following command:

> grep FAIL_DELAY /etc/login.defs
FAIL_DELAY 4

If the value of "FAIL_DELAY" is not set to "4", "FAIL_DELAY" is commented out, or "FAIL_DELAY" is missing, then this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to enforce a delay of at least four seconds between logon prompts following a failed logon attempt.

Add or update the following variable in "/etc/login.defs" to match the line below ("FAIL_DELAY" must have a value of "4" or higher):

FAIL_DELAY 4'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38170r619215_chk'
  tag severity: 'medium'
  tag gid: 'V-234982'
  tag rid: 'SV-234982r622137_rule'
  tag stig_id: 'SLES-15-040000'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-38133r619216_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
