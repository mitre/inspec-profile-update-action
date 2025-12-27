control 'SV-254218' do
  title 'Nutanix AOS must enforce 24 hours/1 day as the minimum password lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', %q(Confirm Nutanix AOS is configured to enforce 24 hour/1 day minimum password lifetime.

$ sudo grep -i pass_min_days /etc/login.defs
PASS_MIN_DAYS 1

If the "PASS_MIN_DAYS" parameter value is not "1" or greater, or is commented out, this is a finding.

$ sudo awk -F: '$4 < 1 {print $1 " " $4}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure the password minimum age by running the following command:

$ sudo salt-call state.sls security/CVM/pamCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57703r846740_chk'
  tag severity: 'medium'
  tag gid: 'V-254218'
  tag rid: 'SV-254218r846742_rule'
  tag stig_id: 'NUTX-OS-001340'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-57654r846741_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
