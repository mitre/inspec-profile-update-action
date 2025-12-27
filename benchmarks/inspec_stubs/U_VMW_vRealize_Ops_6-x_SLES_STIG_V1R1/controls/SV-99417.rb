control 'SV-99417' do
  title 'The SLES for vRealize must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify the SLES for vRealize enforces a delay of at least "4" seconds between logon prompts following a failed logon attempt.

Review the file "/etc/login.defs" and verify the parameter "FAIL_DELAY" is a value of "4" or greater. 

Procedure:

# grep FAIL_DELAY /etc/login.defs

The typical configuration looks something like this: 

FAIL_DELAY    4

If the parameter "FAIL_DELAY" does not exists, or is less than "4", this is a finding.'
  desc 'fix', 'Configure SLES for vRealize to enforce a delay of at least "4" seconds between logon prompts following a failed logon attempt. 

Set the parameter "FAIL_DELAY" to a value of "4" or greater. 

Edit the file "/etc/login.defs". Set the parameter "FAIL_DELAY" to a value of "4" or greater. 

The typical configuration looks something like this: 

FAIL_DELAY    4

Save the changes made to the file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88459r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88767'
  tag rid: 'SV-99417r1_rule'
  tag stig_id: 'VROM-SL-001495'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-95509r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
