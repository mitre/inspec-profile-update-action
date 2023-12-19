control 'SV-253898' do
  title 'The Juniper EX switch must be configured to protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network devices providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Junos provides the operational mode commands "show" (to display the contents of a log file) or "clear" (to delete all of the contents of a log file); there is no text editor or other "audit tool" provided in the CLI. Operational and configuration mode commands require assignment of the required permission bit to execute. For example, audit logs are configured in the [edit system] hierarchy and require the "system" permission to view and the "system-control" permission to configure (or permissions set "all"). However, using the allow or deny statements permits adding, or removing, specific commands or configuration hierarchy levels. Adding the "deny-commands "^clear log"" directive to a login class prevents any user assigned to that class from clearing any log file.

Verify the permissions assigned to each login class is appropriate.

In addition to limiting permissions, Junos supports limiting commands and hierarchy levels that would otherwise be permitted. For example, to remove the ability to modify auditing from a login class with the "system-control" or "all" permissions assigned, use the "deny-configuration-regexps [ "system syslog" ]" directive. To prevent administrative users assigned to that same login class from viewing and/or deleting the audit file contents, add the "deny-commands "^(show|clear) log"" directive.

Example login-class definitions:

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

If the network device does not protect its audit tools from unauthorized access, this is a finding.'
  desc 'fix', "Configure the network device to protect audit tools from unauthorized access.

set system login class <name> permissions <permission sets or 'all'>
set system login class <name> deny-commands <appropriate commands to deny>
set system login class <name> deny-configuration-regexps <appropriate configuration hierarchy to deny>

set system login user <account name> class <name>"
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57350r843725_chk'
  tag severity: 'medium'
  tag gid: 'V-253898'
  tag rid: 'SV-253898r879579_rule'
  tag stig_id: 'JUEX-NM-000210'
  tag gtitle: 'SRG-APP-000121-NDM-000238'
  tag fix_id: 'F-57301r843726_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
