control 'SV-32179' do
  title 'The Directory Service Restore Mode (DSRM) password must be changed at least annually.'
  desc 'The Directory Service Restore Mode (DSRM) password, used to log on to a domain controller (DC) when rebooting into the server recovery mode, is very powerful.  With a weak or known password, someone with local access to the DC can reboot the server and copy or modify the Active Directory database without leaving any trace of the activity.

Failure to change the DSRM password periodically could allow compromised of the Active Directory.  It could also allow an unknown (lost) password to go undetected. If not corrected during a periodic review, the problem might surface during an actual recovery operation and delay or prevent the recovery.'
  desc 'check', 'Verify the organization has a process that addresses DSRM password change frequency.

If DSRM passwords are not changed at least annually, this is a finding.'
  desc 'fix', 'Change the DSRM password at least annually.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-72941r2_chk'
  tag severity: 'medium'
  tag gid: 'V-25840'
  tag rid: 'SV-32179r3_rule'
  tag stig_id: 'AD.0151'
  tag gtitle: 'DSRM Password Change Policy'
  tag fix_id: 'F-79247r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Manager'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
