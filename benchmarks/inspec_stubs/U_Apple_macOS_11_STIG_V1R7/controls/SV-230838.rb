control 'SV-230838' do
  title 'The macOS system must use multifactor authentication for local access to privileged and non-privileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged and non-privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include: 
1) something a user knows (e.g., password/PIN);
2) something a user has (e.g., cryptographic identification device, token); and
3) something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'To verify that the system is configured to enforce multi-factor authentication, run the following commands:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep enforceSmartCard

If the results do not show "enforceSmartCard=1", this is a finding.
.'
  desc 'fix', 'This setting is enforced using the "Smart Card Policy" configuration profile. 

Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG must be consulted to ensure continued access to the operating system.'
  impact 0.7
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33783r607401_chk'
  tag severity: 'high'
  tag gid: 'V-230838'
  tag rid: 'SV-230838r599842_rule'
  tag stig_id: 'APPL-11-003020'
  tag gtitle: 'SRG-OS-000107-GPOS-00054'
  tag fix_id: 'F-33756r607402_fix'
  tag satisfies: ['SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000068-GPOS-00036']
  tag 'documentable'
  tag cci: ['CCI-000187', 'CCI-000767', 'CCI-000768']
  tag nist: ['IA-5 (2) (a) (2)', 'IA-2 (3)', 'IA-2 (4)']
end
