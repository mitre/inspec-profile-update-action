control 'SV-79143' do
  title 'All accounts installed with the web server software and tools must have passwords assigned and default passwords changed.'
  desc 'During installation of the web server software, accounts are created for the web server to operate properly. The accounts installed can have either no password installed or a default password, which will be known and documented by the vendor and the user community.

The first things an attacker will try when presented with a login screen are the default user identifiers with default passwords. Installed applications may also install accounts with no password, making the login even easier. Once the web server is installed, the passwords for any created accounts should be changed and documented. The new passwords must meet the requirements for all passwords, i.e., upper/lower characters, numbers, special characters, time until change, reuse policy, etc. 

Normally, a service account is established for OHS.  This is because a privileged account is not desirable and the server is designed to run for long uninterrupted periods of time.  

The SA or Web Manager will need password access to OHS to restart the service in the event of an emergency as OHS is not to restart automatically after an unscheduled interruption.  If the password is not entrusted to an SA or web manager the ability to ensure the availability of OHS is compromised.

Service accounts or system accounts that have no login capability do not need to have passwords set or changed.'
  desc 'check', 'NOTE: Service accounts or system accounts that have no login capability do not need to have passwords set or changed.

Review the web server documentation and deployment configuration to determine what non-service/system accounts were installed by the web server installation process.

Verify the passwords for these accounts have been set and/or changed from the default passwords.

Verify the SA/Web manager are notified of the changed password.

If these accounts still have no password or have default passwords, this is a finding.

If the SA/web manager does not know the changed password, this is a finding.'
  desc 'fix', 'Inform the OHS Administrator as to what the password is for the OS account that owns the OHS Software.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65395r3_chk'
  tag severity: 'medium'
  tag gid: 'V-64653'
  tag rid: 'SV-79143r2_rule'
  tag stig_id: 'OH12-1X-000207'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70583r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
