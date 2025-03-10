control 'SV-253902' do
  title 'The Juniper EX switch must be configured to use DoD PKI as multifactor authentication (MFA) for interactive logins.'
  desc 'MFA is when two or more factors are used to confirm the identity of an individual who is requesting access to digital information resources. Valid factors include something the individual knows (e.g., username and password), something the individual has (e.g., a smartcard or token), or something the individual is (e.g., a fingerprint or biometric). Legacy information system environments only use a single factor for authentication, typically a username and password combination. Although two pieces of data are used in a username and password combination, this is still considered single factor because an attacker can obtain access by learning what the user knows. 

Common attacks against single-factor authentication are attacks on user passwords. These attacks include brute force password guessing, password spraying, and password credential stuffing. MFA, along with strong user account hygiene, helps mitigate the threat of having account passwords discovered by an attacker. Even in the event of a password compromise, with MFA implemented and required for interactive login, the attacker still needs to acquire something the user has or replicate a piece of user’s biometric digital presence.

Private industry recognizes and uses a wide variety of MFA solutions. However, DoD public key infrastructure (PKI) is the only prescribed method approved for DoD organizations to implement MFA. This requirement is used in conjunction with the use of a centralized authentication server (e.g., AAA, RADIUS, LDAP), a separate but equally important requirement. The centralized authentication server will provide the second phase of authentication (the digital presence of the PKI ID as a valid user in the requested security domain) and authorization. 

Junos currently supports PAP and MS-CHAPv2 for administrative authentication. To mitigate this risk, sites must configure the authorized CAC alternative YubiKey One-Time Password (OTP). The OTP uses AES (AES256 is preferred by DoD) encrypted on the token prior to transmission and is valid only once. When using the authorized CAC alternative SecureID, the credential is valid for 60 seconds or first use, and is valid only once. The single local account (the account of last resort) password is securely hashed in Junos and never transmitted.

To support the authorized CAC alternatives, configure Junos for RADIUS and point to the appropriate authentication server.

If DoD PKI is not used but the network device uses an alternative FIPS 140-2 compliant, Cryptographic Module Validation Program (CMVP) validated OTP password solution, this requirement can be downgraded to a CAT III. Alternative MFA solutions for network devices with basic user interfaces (e.g., L2 switch with only SSH access) have been evaluated by the DoD Privileged User Working Group (PUWG). Current alternatives include RSA SecureID tokens and YubiKey One Time Password (OTP) tokens.'
  desc 'check', 'Verify the network device is configured to use DoD PKI as MFA for interactive logins. Evidence of successful configuration is usually indicated by a prompt for the user to insert a smartcard. If the smartcard is already inserted, the network device will prompt the user to enter the corresponding PIN, which unlocks the certificate keystore on the smartcard. 

If the network device is not configured to use DoD PKI as MFA for interactive logins, this is a finding. 

If the PKI authenticated user is not mapped to the effective local user account, this is a finding.

Note: Alternative MFA solutions for network devices with basic user interfaces (e.g., L2 switch with only SSH access) have been evaluated by the DoD Privileged User Working Group (PUWG). Current alternatives include RSA SecureID tokens and YubiKey OTP tokens. To use an alternative MFA solution, a business case and risk assessment must be presented to the Authorizing Official (AO) for review and acceptance. AOs may choose to accept the risk of using one of these alternatives in a target environment based on the business case that was presented. In this case, it is the responsibility of the AO to determine if the risk should be downgraded to a CAT II or a CAT III based on the risk assessment of the target environment.

If DoD PKI is not used but the network device uses an alternative FIPS 140-2 compliant, CMVP-validated OTP password solution, this requirement can be downgraded to a CAT III. 

Juniper devices fully support authorized alternatives such as the RSA SecureID and Yubico YubiKey OTP tokens.

Verify the device is configured with template accounts and a RADIUS server.
[edit system login]
:
:
user <account name> {
	uid 2015;
	class <name>;
}
:
Note: Accounts without an authentication stanza are template accounts, must be externally authenticated, and cannot log in locally.

[edit system radius-server]
<RSA SecureID or Yubico YubiKey server address> {
    secret "...<hashed PSK>..."; ## SECRET-DATA
}

Note: Other mitigation strategies that have not been evaluated by the DoD PUWG may include the use of one or more industry solutions. One-time password/PIN/passcodes (OTP), one-time URLs, time-based tokens, and biometrics are examples of such solutions. While AOs may choose to accept the risk of using these alternatives on a case-by-case basis, for DoD the risk of using these alternatives should never be mitigated below a CAT II.

Note: This requirement is not applicable to the emergency account of last resort or for service accounts (noninteractive users). Examples of service accounts include remote service brokers such as AAA, syslog, etc.'
  desc 'fix', %q(Configure the Juniper EX switch to use DoD PKI MFA for interactive logins.

set system login class <name> permissions <permission sets or 'all'>
set system login class <name> deny-commands <appropriate commands to deny>
set system login class <name> deny-configuration-regexps <appropriate configuration hierarchy to deny>

set system login user <account name> class <name>

set system radius-server <RSA SecureID or Yubico YubiKey server address> secret "<PSK>"
-or-
prompt system radius-server <RSA SecureID or Yubico YubiKey server address> secret
New secret (secret): <PSK> 
Retype new secret (secret): <confirm PSK>

Note: The PSK is not echoed to the screen.)
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57354r843737_chk'
  tag severity: 'high'
  tag gid: 'V-253902'
  tag rid: 'SV-253902r843739_rule'
  tag stig_id: 'JUEX-NM-000250'
  tag gtitle: 'SRG-APP-000149-NDM-000247'
  tag fix_id: 'F-57305r843738_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
