control 'SV-234889' do
  title 'The SUSE operating system must be configured to create or update passwords with a minimum lifetime of 24 hours (one day).'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', %q(Verify the SUSE operating system creates or updates passwords with minimum password age of one day or greater.

To check that the SUSE operating system enforces 24 hours/one day as the minimum password age, run the following command:

> grep '^PASS_MIN_DAYS' /etc/login.defs

PASS_MIN_DAYS 1

If no output is produced, or if "PASS_MIN_DAYS" does not have a value of "1" or greater, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to enforce 24 hours/one day or greater as the minimum password age.

Edit the file "/etc/login.defs" and add or correct the following line. Replace [DAYS] with the appropriate amount of days:

PASS_MIN_DAYS [DAYS]

The DoD requirement is "1" but a greater value is acceptable.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38077r618936_chk'
  tag severity: 'medium'
  tag gid: 'V-234889'
  tag rid: 'SV-234889r622137_rule'
  tag stig_id: 'SLES-15-020200'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-38040r618937_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
