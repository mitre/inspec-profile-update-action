control 'SV-253922' do
  title 'The Juniper EX switch must be configured to prohibit installation of software without explicit privileged status.'
  desc 'Allowing anyone to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. This requirement applies to code changes and upgrades for all network devices.'
  desc 'check', 'Determine if the network device prohibits installation of software without explicit privileged status.  This requirement may be verified by demonstration or configuration review.

Juniper switches use role-based access controls (RBAC) to assign privilege levels. Account definitions in Junos are either "local" or "template", discriminated by the presence of an authentication stanza. Local accounts have an authentication stanza and support both external and local authentication. Template accounts do not have an authentication stanza and only support external authentication. Every account (local and template) must be assigned a login class by an authorized administrator.

Installation of firmware requires the maintenance permission bit. However, even with that bit set, software installation can be limited by the "deny-commands" statement (e.g., deny-commands "^request system software"). The command takes a regular expression (REGEX) enclosed in double quotes (").

Verify each account is assigned a login class with appropriate permissions based upon organizational requirements. Login classes support optional allow- and deny- directives as shown in the examples. Organizational requirements may require different allow- and deny- directives or no directives at all.

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

If installation of software is not prohibited without explicit privileged status, this is a finding.'
  desc 'fix', "Configure the network device to prohibit installation of software without explicit privileged status.

set system login class <name> permissions <permission sets or 'all'>
set system login class <name> deny-commands <appropriate commands to deny>
set system login class <name> deny-configuration-regexps <appropriate configuration hierarchy to deny>

set system login user <account name> class <name>"
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57374r843797_chk'
  tag severity: 'medium'
  tag gid: 'V-253922'
  tag rid: 'SV-253922r879751_rule'
  tag stig_id: 'JUEX-NM-000450'
  tag gtitle: 'SRG-APP-000378-NDM-000302'
  tag fix_id: 'F-57325r843798_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
