control 'SV-209624' do
  title 'The macOS system must use multifactor authentication in the establishment of nonlocal maintenance and diagnostic sessions.'
  desc 'If maintenance tools are used by unauthorized personnel, they may accidentally or intentionally damage or compromise the system. The act of managing systems and applications includes the ability to access sensitive application information, such as system configuration details, diagnostic information, user information, and potentially sensitive application data.

Some maintenance and test tools are either standalone devices with their own operating systems or are applications bundled with an operating system.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.'
  desc 'check', 'If the system is connected to a directory server, this is Not Applicable.

The following command ensures that a mandatory smart card policy is enforced:

# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep enforceSmartCard 
enforceSmartCard=1

If the command returns null, or any other value, this is a finding.

The following command ensures that passwords are disabled in the SSHD configuration file:

# grep -e ^[\\#]*PasswordAuthentication.* -e ^[\\#]*ChallengeResponseAuthentication.* /etc/ssh/sshd_config
If this command returns null, or anything other than exactly this text, with no leading hash(#), this is a finding:

"PasswordAuthentication no
ChallengeResponseAuthentication no"'
  desc 'fix', %q(For non-directory bound systems, this setting is enforced using the "Smart Card Policy" configuration profile. 

Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.

To ensure that passcode based logins are disabled in sshd, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9875r466285_chk'
  tag severity: 'medium'
  tag gid: 'V-209624'
  tag rid: 'SV-209624r610285_rule'
  tag stig_id: 'AOSX-14-003024'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-9875r466286_fix'
  tag 'documentable'
  tag legacy: ['V-95977', 'SV-105115']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
