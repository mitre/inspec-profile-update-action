control 'SV-47865' do
  title 'Policy must require that administrative user accounts not be used with applications that access the internet, such as web browsers, or with potential internet sources, such as email.'
  desc 'Using applications that access the internet or have potential internet sources using administrative privileges exposes a system to compromise.  If a flaw in an application is exploited while running as a privileged user, the entire system could be compromised.  Web browsers and email are common attack vectors for introducing malicious code and must not be run with an administrative user account.

Since administrative user accounts may generally change or work around technical restrictions for running a web browser or other applications, it is essential that policy requires administrative users not access the internet or use applications, such as email.

The policy should define specific exceptions for local service administration.  These exceptions may include HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.'
  desc 'check', 'Determine if site policy prohibits the use of applications that access the internet, such as web browsers, or with potential internet sources, such as email, by administrative user accounts, except as necessary for local service administration.  If it does not, this is a finding.'
  desc 'fix', 'Establish a site policy to prohibit the use applications that access the internet, such as web browsers, or with potential internet sources, such as email, by administrative user accounts.  Ensure the policy is enforced.'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-44695r2_chk'
  tag severity: 'high'
  tag gid: 'V-36451'
  tag rid: 'SV-47865r1_rule'
  tag stig_id: '1.006-01'
  tag gtitle: 'Accounts with administrative privileges Internet access'
  tag fix_id: 'F-40992r3_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
