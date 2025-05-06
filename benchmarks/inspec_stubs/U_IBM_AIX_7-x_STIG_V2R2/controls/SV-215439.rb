control 'SV-215439' do
  title 'AIX must have the have the PowerSC Multi Factor Authentication Product configured.'
  desc 'To assure accountability and prevent unauthenticated access, privileged and non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 
Multifactor authentication uses two or more factors to achieve authentication.

Factors include: 
1. Something you know (e.g., password/PIN);
2. Something you have (e.g., cryptographic identification device, token); and
3. Something you are (e.g., biometric).

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', %q(Verify /etc/security/pmfa/pam_pmfa.conf is configured correctly.

# grep -i "trustedcas" /etc/security/pmfa/pam_pmfa.conf | grep -v '#'

TRUSTEDCAS = /<path_to_file>/server_ca.pem

Note: Verify with the SA/ISSO as to the location of the "server_ca.pem" file.

If "TRUSTEDCAS" is not configured to point to a valid "server_ca.pem" file or is missing, this is a finding.

# grep -i "mfa-url" /etc/security/pmfa/pam_pmfa.conf | grep -v '#'

MFA-URL = https://pmfa.example.com:6793/policyAuth/

If the "MFA-URL" is missing or does not point to a valid address, this is a finding.

# grep -i "server-version" /etc/security/pmfa/pam_pmfa.conf | grep -v '#'

SERVER-VERSION = 2

If "SERVER-VERSION" is missing or is not set to "2", this is a finding.

# grep -i "ctc-prompt" /etc/security/pmfa/pam_pmfa.conf | grep -v '#'

CTC-PROMPT-ONLY = Y

If "CTC-PROMPT-ONLY" is missing or is not set to "Y", this is a finding.)
  desc 'fix', 'Add or update the following lines in the "/etc/security/pmfa/pam_pmfa.conf" file:

TRUSTEDCAS = /<path_to_file>/server_ca.pem

Note: Verify with the SA/ISSO as to the location of the "server_ca.pem" file.

MFA-URL = https://pmfa.example.com:6793/policyAuth/

SERVER-VERSION = 2

CTC-PROMPT-ONLY = Y'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16637r294768_chk'
  tag severity: 'medium'
  tag gid: 'V-215439'
  tag rid: 'SV-215439r508663_rule'
  tag stig_id: 'AIX7-00-003203'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16635r294769_fix'
  tag 'documentable'
  tag legacy: ['SV-103035', 'V-92947']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
