control 'SV-234165' do
  title 'The FortiGate device must have only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc %q(Authentication for administrative (privilege-level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the "account of last resort" since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit must be added to the envelope as a record. Administrators must secure the credentials and disable the root account (if possible) when not needed for system administration functions.)
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Verify the admin account is the only account configured as Type Local.

If more than one local user account exists, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Review list of administrators and determine if any besides admin have Type listed as Local
4. For any with type Local, click Administrator, and then click Edit to change to remote authentication, or Delete to remove the administrator
5. To change the administrator to remote authentication, in Type select "Match a user on a remote server group".
6. In Remote User Group, select the appropriate configured remote user group.
7. Click OK.
8. Repeat for all administrators, besides admin that have local authentication listed.
9. Click OK.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37350r611682_chk'
  tag severity: 'medium'
  tag gid: 'V-234165'
  tag rid: 'SV-234165r850511_rule'
  tag stig_id: 'FGFW-ND-000030'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-37315r850510_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
