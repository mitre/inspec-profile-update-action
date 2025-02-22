control 'SV-32288' do
  title 'The maximum password age must be configured to 60 days or less.'
  desc 'The longer passwords are in use, the greater the opportunity for someone to gain unauthorized knowledge of them.  Scheduled changing of passwords hinders the ability of unauthorized system users to crack passwords and gain access to a system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies >> Password Policy.

If the value for the "Maximum password age" is greater than "60" days, this is a finding.
If the value is set to "0" (never expires), this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Maximum password age" to "60" days or less (excluding "0", which is unacceptable).'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-60977r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1104'
  tag rid: 'SV-32288r2_rule'
  tag gtitle: 'Maximum Password Age'
  tag fix_id: 'F-65707r3_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
