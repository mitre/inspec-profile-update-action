control 'SV-234890' do
  title 'The SUSE operating system must employ user passwords with a minimum lifetime of 24 hours (one day).'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', %q(Verify the SUSE operating system enforces a minimum time period between password changes for each user account of one day or greater.

Check the minimum time period between password changes for each user account with the following command:

> sudo awk -F: '$4 < 1 {print $1 ":" $4}' /etc/shadow

smithj:1

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to enforce 24 hours/one day or greater as the minimum password age for user accounts.

Change the minimum time period between password changes for each [USER] account to "1" day with the command, replacing [USER] with the user account that must be changed:

> sudo passwd -n 1 [USER]'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38078r618939_chk'
  tag severity: 'medium'
  tag gid: 'V-234890'
  tag rid: 'SV-234890r622137_rule'
  tag stig_id: 'SLES-15-020210'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-38041r618940_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
