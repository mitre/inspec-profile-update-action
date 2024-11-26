control 'SV-240549' do
  title 'The SLES for vRealize must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify the SLES for vRealize enforces a delay of at least "4" seconds between logon prompts following a failed logon attempt.

Verify the use of the "pam_faildelay" module.

# grep pam_faildelay /etc/pam.d/common-auth*

The typical configuration looks something like this:

#delay is in micro seconds
auth    required    pam_faildelay.so    delay=4000000

If the line is not present, this is a finding.'
  desc 'fix', 'Configure the SLES for vRealize to enforce a delay of at least "4" seconds between logon prompts following a failed logon attempt with the following command:

# sed -i "/^[^#]*pam_faildelay.so/ c\\auth required pam_faildelay.so delay=4000000" /etc/pam.d/common-auth-vmware.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43782r671386_chk'
  tag severity: 'medium'
  tag gid: 'V-240549'
  tag rid: 'SV-240549r671388_rule'
  tag stig_id: 'VRAU-SL-001525'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-43741r671387_fix'
  tag 'documentable'
  tag legacy: ['SV-100525', 'V-89875']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
