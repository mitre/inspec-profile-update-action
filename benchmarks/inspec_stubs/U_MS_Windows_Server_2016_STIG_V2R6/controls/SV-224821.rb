control 'SV-224821' do
  title 'Administrative accounts must not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.'
  desc 'Using applications that access the Internet or have potential Internet sources using administrative privileges exposes a system to compromise. If a flaw in an application is exploited while running as a privileged user, the entire system could be compromised. Web browsers and email are common attack vectors for introducing malicious code and must not be run with an administrative account.

Since administrative accounts may generally change or work around technical restrictions for running a web browser or other applications, it is essential that policy require administrative accounts to not access the Internet or use applications such as email.

The policy should define specific exceptions for local service administration. These exceptions may include HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.

Whitelisting can be used to enforce the policy to ensure compliance.'
  desc 'check', 'Determine whether organization policy, at a minimum, prohibits administrative accounts from using applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, except as necessary for local service administration.

If it does not, this is a finding.

The organization may use technical means such as whitelisting to prevent the use of browsers and mail applications to enforce this requirement.'
  desc 'fix', 'Establish a policy, at minimum, to prohibit administrative accounts from using applications that access the Internet, such as web browsers, or with potential Internet sources, such as email. Ensure the policy is enforced.

The organization may use technical means such as whitelisting to prevent the use of browsers and mail applications to enforce this requirement.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26512r465365_chk'
  tag severity: 'high'
  tag gid: 'V-224821'
  tag rid: 'SV-224821r569186_rule'
  tag stig_id: 'WN16-00-000040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26500r465366_fix'
  tag 'documentable'
  tag legacy: ['SV-87877', 'V-73225']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
