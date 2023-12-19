control 'SV-99115' do
  title 'SLES for vRealize must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', %q(To check that SLES for vRealize enforces 24 hours/1 day as the minimum password age, run the following command:

# grep PASS_MIN_DAYS /etc/login.defs | grep -v '#'

The DoD requirement is "1".

If "PASS_MIN_DAYS" is not set to the required value, this is a finding.)
  desc 'fix', 'To configure SLES for vRealize to enforce 24 hours/1 day as the minimum password age, edit the file "/etc/login.defs" with the following command:

# sed -i "/^[^#]*PASS_MIN_DAYS/ c\\PASS_MIN_DAYS 1" /etc/login.defs'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88157r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88465'
  tag rid: 'SV-99115r1_rule'
  tag stig_id: 'VROM-SL-000375'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-95207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
