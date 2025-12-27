control 'SV-253901' do
  title 'The Juniper EX switch must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account is created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable access to the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Review the network device configuration to determine if an account of last resort is configured. Verify default admin and other vendor-provided accounts are disabled, removed, or renamed where possible. Verify the username and password for the account of last resort is contained within a sealed envelope and kept in a safe. 

There are no default passwords in Junos and the root account cannot be renamed or disabled. The root account password should be saved in the same manner as the account of last resort. 

Verify direct root login is disabled.
[edit system services ssh]
root-login deny;

[edit system ports]
console {
    log-out-on-disconnect;
    insecure;
}
Note: Setting the console port "insecure" prevents direct root login but also prevents password recovery without knowledge of the root password.

Verify only a single local account has an authentication stanza. Local accounts without an authentication stanza are "template accounts" and must be externally authenticated. Template accounts must match the logging-in username or a returned Vendor Specific Attribute (VSA) and are used to map permissions (assigned in the login class) to the user. This example assumes a working external authentication server and appropriate authentication order.

[edit system login]
:
:
user <account of last resort name> {
    uid 2004;
    class <class name>;
    authentication {
        encrypted-password "$6$0/BgZc6n$BIY..<snip>..vLzjWpYq2D/"; ## SECRET-DATA
    }
}
user auditor {
    uid 2010;
    class <class name>;
}

If one local account does not exist for use as the account of last resort, this is a finding.'
  desc 'fix', 'Configure the device to only allow one local account for use as the account of last resort.   

Disable direct root login:
set system services ssh root-login deny
set system ports console insecure

Configure the account of last resort:
set system login user <account of last resort name> class <class name>
set system login user <account of last resort name> authentication plain-text-password
New password: <password - not echoed to the screen>
Retype new password: <password verification - not echoed to the screen>

Set all other template accounts:
set system login user <template account 1> class <class 1>
set system login user <template account 2> class <class 2>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57353r843734_chk'
  tag severity: 'medium'
  tag gid: 'V-253901'
  tag rid: 'SV-253901r843736_rule'
  tag stig_id: 'JUEX-NM-000240'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-57304r843735_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
