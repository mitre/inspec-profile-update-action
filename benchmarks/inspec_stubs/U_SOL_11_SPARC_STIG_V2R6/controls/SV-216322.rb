control 'SV-216322' do
  title 'The operating system must automatically terminate temporary accounts within 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation. 

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation. 

If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

When temporary and emergency accounts are created, there is a risk the temporary account may remain in place and active after the need for the account no longer exists.

To address this, in the event temporary accounts are required, accounts designated as temporary in nature must be automatically terminated after 72 hours. Such a process and capability greatly reduces the risk of accounts being misused, hijacked, or data compromised.'
  desc 'check', %q(The root role is required.

Determine if an expiration date is set for temporary accounts.

# logins -aox |awk -F: '($14 == "0") {print}'

This command produces a list of accounts with no expiration date set. If any of these accounts are temporary accounts, this is a finding.

# logins -aox |awk -F: '($14 != "0") {print}'

This command produces a list of accounts with an expiration date set as defined in the last field. If any accounts have a date that is not within 72 hours, this is a finding.)
  desc 'fix', 'The User Security role is required.

Apply an expiration date to temporary users.

# pfexec usermod -e "[date]" [username]

Enter the date in the form mm/dd/yyyy such that it is within 72 hours.'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17558r371054_chk'
  tag severity: 'low'
  tag gid: 'V-216322'
  tag rid: 'SV-216322r603267_rule'
  tag stig_id: 'SOL-11.1-040020'
  tag gtitle: 'SRG-OS-000002'
  tag fix_id: 'F-17556r371055_fix'
  tag 'documentable'
  tag legacy: ['V-47949', 'SV-60821']
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
