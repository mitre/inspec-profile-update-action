control 'SV-239647' do
  title 'The SLES for vRealize must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Check the value of the "FAIL_DELAY" variable and the ability to use it:

# grep FAIL_DELAY /etc/login.defs 

The following result should be displayed:

FAIL_DELAY 4

If the value does not exist, or is less than "4", this is a finding.

Check for the use of "pam_faildelay":

# grep pam_faildelay /etc/pam.d/common-auth*

The following result should be displayed:

/etc/pam.d/common-auth:auth optional pam_faildelay.so

If the "pam_faildelay.so" module is not listed or is commented out, this is a finding.'
  desc 'fix', 'Add the "pam_faildelay" module and set the "FAIL_DELAY" variable.

Edit the "/etc/login.defs" file and set the value of the "FAIL_DELAY" variable to "4" or more.

Edit "/etc/pam.d/common-auth" and add a "pam_faildelay" entry if one does not exist, such as: 

auth optional pam_faildelay.so'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42880r662390_chk'
  tag severity: 'medium'
  tag gid: 'V-239647'
  tag rid: 'SV-239647r662392_rule'
  tag stig_id: 'VROM-SL-001490'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-42839r662391_fix'
  tag 'documentable'
  tag legacy: ['SV-99415', 'V-88765']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
