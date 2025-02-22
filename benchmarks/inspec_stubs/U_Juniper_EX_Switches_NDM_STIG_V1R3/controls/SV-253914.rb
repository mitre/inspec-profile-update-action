control 'SV-253914' do
  title 'The Juniper device must be configured to only allow authorized administrators to view or change the device configuration, system files, and other files stored either in the device or on removable media (such as a flash drive).'
  desc 'This requirement is intended to address the confidentiality and integrity of system information at rest (e.g., network device rule sets) when it is located on a storage device within the network device or as a component of the network device. This protection is required to prevent unauthorized alteration, corruption, or disclosure of information when not stored directly on the network device.

Files on the network device or on removable media used by the device must have their permissions set to allow read or write access to those accounts that are specifically authorized to access or change them. Note that different administrative accounts or roles will have varying levels of access.

File permissions must be set so that only authorized administrators can read or change their contents. Whenever files are written to removable media and the media removed from the device, the media must be handled appropriately for the classification and sensitivity of the data stored on the device.'
  desc 'check', 'The Junos operating system maintains file permissions for all files on the device and cannot be configured otherwise. Because Juniper digitally signs and used cryptographic hashes, modified system files (specifically binary files) will invalidate the signature/hash and will not be executed.

The Junos OS enforces the permissions assigned to each user to restrict access to system, configuration, and audit files via login classes.  Every account must be assigned a login class by an authorized administrator.  

Verify each account is assigned a login class with appropriate permissions based on organizational requirements. Login classes support optional allow- and deny- directives as shown in the examples. Organizational requirements may require different allow- and deny- directives or no directives at all.

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

Verify "no-world-readable" for archived log files.
[edit system syslog]
archive size <file size> files <number of files> no-world-readable;

If any files allow read or write access by accounts not specifically authorized access or by nonprivileged accounts, this is a finding.'
  desc 'fix', "Configure the device to enforce RBAC permissions so only authorized administrators can read or change file contents.

set system login class <name> permissions <permission sets or 'all'>
set system login class <name> deny-commands <appropriate commands to deny>
set system login class <name> deny-configuration-regexps <appropriate configuration hierarchy to deny>

set system syslog archive size <file size> files <number of files> no-world-readable"
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57366r843773_chk'
  tag severity: 'high'
  tag gid: 'V-253914'
  tag rid: 'SV-253914r879642_rule'
  tag stig_id: 'JUEX-NM-000370'
  tag gtitle: 'SRG-APP-000231-NDM-000271'
  tag fix_id: 'F-57317r843774_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
