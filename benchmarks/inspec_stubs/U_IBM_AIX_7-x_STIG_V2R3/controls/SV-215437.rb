control 'SV-215437' do
  title 'The AIX operating system must be configured to authenticate using Multi Factor Authentication.'
  desc 'To assure accountability and prevent unauthenticated access, privileged and non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 
Multifactor authentication uses two or more factors to achieve authentication.

Factors include: 
1. Something you know (e.g., password/PIN);
2. Something you have (e.g., cryptographic identification device, token); and
3. Something you are (e.g., biometric).

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', 'Verify the global "auth_type" is configured to use PAM: 

# grep auth_type /etc/security/login.cfg |grep AUTH 

auth_type = PAM_AUTH

If "auth_type" is not set to "PAM_AUTH", this is a finding.


Verify that the user stanza is configured to use PAM:

# lssec -f /etc/security/login.cfg -susw -a auth_type
   
usw auth_type=PAM_AUTH

If "auth_type" is not set to "PAM_AUTH", this is a finding.'
  desc 'fix', 'Run the following command to set the global and user stanza "auth_type":

# chsec -f /etc/security/login.cfg -susw -a auth_type=PAM_AUTH'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16635r294762_chk'
  tag severity: 'medium'
  tag gid: 'V-215437'
  tag rid: 'SV-215437r508663_rule'
  tag stig_id: 'AIX7-00-003201'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16633r294763_fix'
  tag 'documentable'
  tag legacy: ['V-92943', 'SV-103031']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
