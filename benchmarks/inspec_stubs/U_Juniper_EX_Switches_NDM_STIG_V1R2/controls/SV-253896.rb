control 'SV-253896' do
  title 'The Juniper EX switch must be configured to protect audit information from unauthorized modification.'
  desc 'Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit network device activity.

If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the network device must protect audit information from unauthorized modification. 

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Some commonly employed methods include ensuring log files receive the proper file system permissions and limiting log data locations. 

Network devices providing a user interface to audit data will leverage user permissions and roles identifying the user accessing the data and the corresponding rights that the user enjoys to make access decisions regarding the modification of audit data.'
  desc 'check', 'Determine if the network device protects audit information from any type of unauthorized modification with such methods as ensuring log files receive the proper file system permissions, limiting log data locations, and leveraging user permissions and roles to identify the user accessing the data and the corresponding rights that the user enjoys. This requirement may be verified by demonstration, configuration, or validated test results. 

Juniper switches use role-based access controls (RBAC) to assign privilege levels. Account definitions in Junos are either "local" or "template", discriminated by the presence of an authentication stanza. Local accounts have an authentication stanza and support both external and local authentication. Template accounts do not have an authentication stanza and only support external authentication. Every account (local and template) must be assigned a login class by an authorized administrator.

Audit logs are configured in the [edit system] hierarchy and require the "system" permission to view and the "system-control" permission to configure (or permissions set "all"). However, using the allow or deny statements permits adding, or removing, specific commands or configuration hierarchy levels. 

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

If the network device does not protect audit information from unauthorized modification, this is a finding.'
  desc 'fix', "Configure the network device to protect audit information from unauthorized modification.

set system login class <name> permissions <permission sets or 'all'>
set system login class <name> deny-commands <appropriate commands to deny>
set system login class <name> deny-configuration-regexps <appropriate configuration hierarchy to deny>

set system login user <account name> class <name>"
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57348r843719_chk'
  tag severity: 'medium'
  tag gid: 'V-253896'
  tag rid: 'SV-253896r843721_rule'
  tag stig_id: 'JUEX-NM-000190'
  tag gtitle: 'SRG-APP-000119-NDM-000236'
  tag fix_id: 'F-57299r843720_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
