control 'SV-253947' do
  title 'The Juniper EX switch must prevent nonprivileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Nonprivileged users are individuals that do not possess appropriate authorizations.'
  desc 'check', 'If the network device is configured to use a AAA service account, and the AAA broker is configured to assign authorization levels based on centralized user account group memberships on behalf of the network device, that will satisfy this objective. Because the responsibility for meeting this objective is transferred to the AAA broker, this requirement is not applicable for the local network device. This requirement may be verified by demonstration or configuration review.

Juniper switches use role-based access controls (RBAC) to assign privilege levels. Account definitions in Junos are either "local" or "template", discriminated by the presence of an authentication stanza. Local accounts have an authentication stanza and support both external and/or local authentication depending upon the authentication order. Template accounts do not have an authentication stanza and only support external authentication. Every account (local and template) must be assigned a login class by an authorized administrator.

Verify each account is assigned a login class with appropriate permissions based upon organizational requirements. Login classes support optional allow- and deny- directives as shown in the examples. Organizational requirements may require different allow- and deny- directives, or no directives at all.

[edit system login]
class <name> {
	idle-timeout 10;
	permissions all;
	deny-commands "^clear (log|security log)|^(clear|show) security alarms alarm-type idp|^request (security|system set-encryption-key|system firmware upgrade re|system decrypt)|^rollback";
	deny-configuration-regexps [ "security alarms potential-violation idp" "security (ike|ipsec) (policy|proposal)" "security ipsec ^vpn$ .* manual (authentication|encryption|protocol|spi)" "security log" "system fips self-test after-key-generation" "system (archival|syslog|root-authentication|authentication-order|master-password)" "system services ssh (protocol-version|root-login)" "system login password" "system login user [a-zA-Z0-9_-]+ (authentication|class)" "system login class [a-zA-Z0-9_-]+ (permissions|deny-|allow-)" ];
}
class <name-1> {
	idle-timeout 10;
	permissions [ configure maintenance security system-control trace view-configuration ];
	allow-commands "^clear (log|security log)|^show cli authorization";
	deny-commands "^clear (security alarms|system login lockout)|^file (copy|delete|list|rename|show)|^request (security|system set-encryption-key|system firmware upgrade re)|^rollback|^set date|^show security (alarms|dynamic-policies|match-policies|policies)|^start shell|^request system (decrypt|halt|reboot|software|zeroize)";
	deny-configuration-regexps [ "system (login|internet-options|scripts|services|time-zone|^[a-r]+)" "security services event-options" ];
	security-role audit-administrator;
}

Example local and template accounts:

user <account of last resort> {
	uid 2000;
	class <name>;
	authentication {
		encrypted-password "$6$HEQnJP/W$/QD...<snip>...5r./"; ## SECRET-DATA
	}
}
user <account name> {
	uid 2015;
	class <name-1>;
}
Note: Accounts without an authentication stanza are template accounts, must be externally authenticated, and cannot log in locally.

Verify the network device is configured to assign appropriate user roles or access levels to authenticated users. This requirement may be verified by demonstration or configuration review. 

If the Juniper EX switch does not prevent nonprivileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures, this is a finding.'
  desc 'fix', "Configure the network device to assign appropriate user roles or access levels to authenticated users, or configure the network device to leverage an AAA solution that will satisfy this objective.

set system login class <name> permissions <permission sets or 'all'>
set system login class <name> deny-commands <appropriate commands to deny>
set system login class <name> deny-configuration-regexps <appropriate configuration hierarchy to deny>

set system login user <account name> class <name>"
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57399r843872_chk'
  tag severity: 'high'
  tag gid: 'V-253947'
  tag rid: 'SV-253947r843874_rule'
  tag stig_id: 'JUEX-NM-000930'
  tag gtitle: 'SRG-APP-000340-NDM-000288'
  tag fix_id: 'F-57350r843873_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
