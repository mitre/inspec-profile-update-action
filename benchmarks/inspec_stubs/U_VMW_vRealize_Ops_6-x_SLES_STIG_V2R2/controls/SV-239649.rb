control 'SV-239649' do
  title 'The SLES for vRealize must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify SLES for vRealize enforces a delay of at least "4" seconds between logon prompts following a failed logon attempt.

Verify the use of the "pam_faildelay" module.

Procedure:

# grep pam_faildelay /etc/pam.d/common-auth*

The typical configuration looks something like this:

#delay is in micro seconds
auth    required    pam_faildelay.so    delay=4000000

If the line is not present, this is a finding.'
  desc 'fix', 'Configure SLES for vRealize to enforce a delay of at least "4" seconds between logon prompts following a failed logon attempt with the following command:

# sed -i "/^[^#]*pam_faildelay.so/ c\\auth required pam_faildelay.so delay=4000000" /etc/pam.d/common-auth-vmware.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42882r662396_chk'
  tag severity: 'medium'
  tag gid: 'V-239649'
  tag rid: 'SV-239649r662398_rule'
  tag stig_id: 'VROM-SL-001500'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-42841r662397_fix'
  tag 'documentable'
  tag legacy: ['SV-99419', 'V-88769']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
