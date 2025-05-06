control 'SV-257233' do
  title 'The macOS system must use multifactor authentication for local access to privileged and nonprivileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged and nonprivileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include: 
1) something a user knows (e.g., password/PIN);
2) something a user has (e.g., cryptographic identification device, token); and
3) something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

The DOD CAC with DOD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'Verify the macOS system is configured to enforce multifactor authentication with the following commands:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "enforceSmartCard"

enforceSmartCard = 1;

If "enforceSmartCard" is not set to "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to enforce multifactor authentication by installing the "Smart Card Policy" configuration profile.

Note: To ensure continued access to the operating system, consult the supplemental guidance provided with the STIG before applying the "Smart Card Policy".'
  impact 0.7
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60918r905330_chk'
  tag severity: 'high'
  tag gid: 'V-257233'
  tag rid: 'SV-257233r905332_rule'
  tag stig_id: 'APPL-13-003020'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag fix_id: 'F-60859r905331_fix'
  tag satisfies: ['SRG-OS-000068-GPOS-00036', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag cci: ['CCI-000187', 'CCI-000767', 'CCI-000768']
  tag nist: ['IA-5 (2) (a) (2)', 'IA-2 (3)', 'IA-2 (4)']
end
