control 'SV-209623' do
  title 'The macOS system must use multifactor authentication for local and network access to privileged and non-privileged accounts.'
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
  desc 'check', 'If the system is connected to a directory server, this is Not Applicable.

To verify that the system is configured to enforce multi-factor authentication, run the following commands:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep enforceSmartCard

If the results do not show the following, this is a finding.
"enforceSmartCard=1.

Run the following command to disable  password based authentication in SSHD.

/usr/bin/grep -e ^[\\#]*PasswordAuthentication.* -e ^[\\#]*ChallengeResponseAuthentication.* /etc/ssh/sshd_config

If this command returns null, or anything other than exactly this text, with no leading hash(#), this is a finding:

"PasswordAuthentication no
ChallengeResponseAuthentication no"'
  desc 'fix', %q(For non directory bound systems, this setting  is enforced using the "Smart Card Policy" configuration profile. 

Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.

The following commands must be run to disable passcode based authentication for SSHD:

/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9874r466276_chk'
  tag severity: 'medium'
  tag gid: 'V-209623'
  tag rid: 'SV-209623r610285_rule'
  tag stig_id: 'AOSX-14-003020'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-9874r466277_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag legacy: ['V-95565', 'SV-104729']
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)']
end
