control 'SV-225212' do
  title 'The macOS system must use multifactor authentication for local and network access to privileged and non-privileged accounts, the establishment of nonlocal maintenance and diagnostic sessions, and authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged and non-privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include: 
1) something a user knows (e.g., password/PIN);
2) something a user has (e.g., cryptographic identification device, token); and
3) something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet).

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'To verify that the system is configured to enforce multifactor authentication, run the following commands:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep enforceSmartCard

If the results do not show the following, this is a finding:

"enforceSmartCard=1.

Run the following command to disable  password based authentication in SSHD:

/usr/bin/grep -e ^[\\#]*PasswordAuthentication.* -e ^[\\#]*ChallengeResponseAuthentication.* /etc/ssh/sshd_config

If this command returns null, or anything other than exactly the following text, with no leading hash(#), this is a finding:

"PasswordAuthentication no
ChallengeResponseAuthentication no"'
  desc 'fix', %q(For non-directory-bound systems, this setting  is enforced using the "Smart Card Policy" configuration profile. 

Note: Before applying the "Smart Card Policy", consult the supplemental guidance provided with the STIG to ensure continued access to the operating system.

The following commands must be run to disable passcode based authentication for SSHD:
/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config)
  impact 0.7
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26911r485634_chk'
  tag severity: 'high'
  tag gid: 'V-225212'
  tag rid: 'SV-225212r610901_rule'
  tag stig_id: 'AOSX-15-003020'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-26899r485796_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000068-GPOS-00036', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000375-GPOS-00160']
  tag 'documentable'
  tag legacy: ['V-102843', 'SV-111805']
  tag cci: ['CCI-000187', 'CCI-000877', 'CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768', 'CCI-001948']
  tag nist: ['IA-5 (2) (a) (2)', 'MA-4 c', 'IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (11)']
end
