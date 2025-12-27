control 'SV-217321' do
  title 'The Juniper router must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Review the router configuration to verify that a local account for last resort has been configured as shown in the following example:

system {
    authentication-order radius;
    }
    login {
        class ENGINEER {
            permissions all;
            deny-commands "(file delete)";
            deny-configuration "(system syslog)";
        }
         user Last_Resort {
            uid 2000;
            class ENGINEER;
            authentication {
                encrypted-password "$1$CYrhql/I$v2ydLnac9EPdA1F/KvROT1"; ## SECRET-DATA
            }
        }

Note: If there is no response from the authentication server, JUNOS will authenticate using a local account as last resort. It is recommended to not configure password at the end of the authentication order, as JUNOS will attempt to authenticate using a local account upon a rejection from the authentication server if password is in the authentication order. The last resort account is used when the authentication server is down.

If the router is not configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable, this is a finding.'
  desc 'fix', 'Step 1: Configure a class with the necessary privileges to troubleshoot network outage and restore operations as shown in the following example:

[edit system]
set login class ENGINEER permissions all 
set login class ENGINEER deny-configuration "(system syslog)"
set login class ENGINEER deny-commands “(file delete)”

Step 2: Assign the account of last resort to the ENGINEER class.

set user LAST_RESORT class ENGINEER authentication plain-text-password
New password: xxxxxxxxxxxxx

Step 3: Configure the authentication order to use the local account if the authentication server is not reachable as shown in the example below.

[edit system]
set authentication-order radius

Note: If there is no response from the authentication server, JUNOS will authenticate using a local account as last resort. It is recommended to not configure password at the end of the authentication order, as JUNOS will attempt to authenticate using a local account upon a rejection from the authentication server if password is in the authentication order. The last resort account is used when the authentication server is down.'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18548r863255_chk'
  tag severity: 'medium'
  tag gid: 'V-217321'
  tag rid: 'SV-217321r879589_rule'
  tag stig_id: 'JUNI-ND-000490'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-18546r863256_fix'
  tag 'documentable'
  tag legacy: ['SV-101227', 'V-91127']
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
