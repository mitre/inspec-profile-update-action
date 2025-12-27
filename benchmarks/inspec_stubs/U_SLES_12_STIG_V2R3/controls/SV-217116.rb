control 'SV-217116' do
  title 'The SUSE operating system must enforce a delay of at least four (4) seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify the SUSE operating system enforces a delay of at least four (4) seconds between logon prompts following a failed logon attempt.

Check that the SUSE operating system enforces a delay of at least four (4) seconds between logon prompts following a failed logon attempt with the following command:

# grep FAIL_DELAY /etc/login.defs
FAIL_DELAY 4

If the value of "FAIL_DELAY" is not set to "4", "FAIL_DELAY" is commented out, or "FAIL_DELAY" is missing, then this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to enforce a delay of at least four (4) seconds between logon prompts following a failed logon attempt.

Add or update the following variable in "/etc/login.defs" to match the line below ("FAIL_DELAY" must have a value of "4" or higher):

FAIL_DELAY 4'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18344r369504_chk'
  tag severity: 'medium'
  tag gid: 'V-217116'
  tag rid: 'SV-217116r603262_rule'
  tag stig_id: 'SLES-12-010140'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-18342r369505_fix'
  tag 'documentable'
  tag legacy: ['SV-91769', 'V-77073']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
