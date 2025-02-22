control 'SV-48030' do
  title 'The maximum password age must meet requirements.'
  desc 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the passwords.   Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies -> Password Policy.

If the value for the "Maximum password age" is greater than 60 days, this is a finding.  If the value is set to 0 (never expires), this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Maximum Password Age" to "60" days or less (excluding "0" which is unacceptable).'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44768r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1104'
  tag rid: 'SV-48030r1_rule'
  tag stig_id: 'WN08-AC-000005'
  tag gtitle: 'Maximum Password Age'
  tag fix_id: 'F-41168r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
