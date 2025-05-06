control 'SV-217138' do
  title 'The SUSE operating system must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify the SUSE operating system enforces a delay of at least four seconds between logon prompts following a failed logon attempt.

# grep pam_faildelay /etc/pam.d/common-auth*
auth required pam_faildelay.so delay=4000000

If the value of "delay" is not set to "4000000" or greater, "delay" is commented out, "delay" is missing, or the "pam_faildelay" line is missing completely, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to enforce a delay of at least four seconds between logon prompts following a failed logon attempt.

Edit the file "/etc/pam.d/common-auth".

Add a parameter "pam_faildelay" and set it to a value of "4000000" or greater:

# delay is in micro seconds
auth required pam_faildelay.so delay=4000000'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18366r369570_chk'
  tag severity: 'medium'
  tag gid: 'V-217138'
  tag rid: 'SV-217138r603262_rule'
  tag stig_id: 'SLES-12-010370'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-18364r369571_fix'
  tag 'documentable'
  tag legacy: ['SV-91827', 'V-77131']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
