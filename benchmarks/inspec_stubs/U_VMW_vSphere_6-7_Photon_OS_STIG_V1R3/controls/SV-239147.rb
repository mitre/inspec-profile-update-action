control 'SV-239147' do
  title 'The Photon operating system must set the FAIL_DELAY parameter.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'At the command line, execute the following command:

# grep FAIL_DELAY /etc/login.defs 

Expected result:

FAIL_DELAY 4

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/login.defs with a text editor.

Add the following line after the last auth statement:

FAIL_DELAY 4'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42358r675247_chk'
  tag severity: 'medium'
  tag gid: 'V-239147'
  tag rid: 'SV-239147r675249_rule'
  tag stig_id: 'PHTN-67-000076'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-42317r675248_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
