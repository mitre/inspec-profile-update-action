control 'SV-215440' do
  title 'The AIX operating system must be configured to use a valid server_ca.pem file.'
  desc 'To assure accountability and prevent unauthenticated access, privileged and non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 
Multifactor authentication uses two or more factors to achieve authentication.

Factors include: 
1. Something you know (e.g., password/PIN);
2. Something you have (e.g., cryptographic identification device, token); and
3. Something you are (e.g., biometric).

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', %q(Verify the location of the "server_ca.pem" file:

# grep -i "trustedcas" /etc/security/pmfa/pam_pmfa.conf | grep -v '#'

TRUSTEDCAS = /<path_to_file>/server_ca.pem

Verify that the configured "server_ca.pem" file exists in the defined location:

# ls -la /<path_to_file>/server_ca.pem

If the file does not exist, this is a finding.)
  desc 'fix', 'Configure the system to use a valid "server_ca.pem" file.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16638r294771_chk'
  tag severity: 'medium'
  tag gid: 'V-215440'
  tag rid: 'SV-215440r508663_rule'
  tag stig_id: 'AIX7-00-003204'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16636r294772_fix'
  tag 'documentable'
  tag legacy: ['SV-103037', 'V-92949']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
