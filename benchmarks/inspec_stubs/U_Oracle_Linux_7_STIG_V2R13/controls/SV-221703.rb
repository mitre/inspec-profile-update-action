control 'SV-221703' do
  title 'The Oracle Linux operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication.'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following:

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; 

and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

'
  desc 'check', 'Verify the operating system requires multifactor authentication to uniquely identify organizational users using multifactor authentication.

Check to see if smartcard authentication is enforced on the system:
# authconfig --test | grep "pam_pkcs11 is enabled"

If no results are returned, this is a finding.

# authconfig --test | grep "smartcard removal action"

If "smartcard removal action" is blank, this is a finding.

# authconfig --test | grep "smartcard module"

If any of the above checks are not configured, ask the administrator to indicate the AO-approved multifactor authentication in use and the configuration to support it. If there is no evidence of multifactor authentication, this is a finding.'
  desc 'fix', 'Configure the operating system to require individuals to be authenticated with a multifactor authenticator.

Enable smartcard logons with the following commands:

# authconfig --enablesmartcard --smartcardaction=0 --update
# authconfig --enablerequiresmartcard -update

Modify the "/etc/pam_pkcs11/pkcs11_eventmgr.conf" file to uncomment the following line:

#/usr/X11R6/bin/xscreensaver-command -lock

Modify the "/etc/pam_pkcs11/pam_pkcs11.conf" file to use the cackey module if required.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23418r818810_chk'
  tag severity: 'medium'
  tag gid: 'V-221703'
  tag rid: 'SV-221703r818811_rule'
  tag stig_id: 'OL07-00-010500'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-23407r419182_fix'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000109-GPOS-00056', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000108-GPOS-00057', 'SRG-OS-000108-GPOS-00058']
  tag 'documentable'
  tag legacy: ['V-99145', 'SV-108249']
  tag cci: ['CCI-000764', 'CCI-000767', 'CCI-000768', 'CCI-000770']
  tag nist: ['IA-2', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (5)']
end
