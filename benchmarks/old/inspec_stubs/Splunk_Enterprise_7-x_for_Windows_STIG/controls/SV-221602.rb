control 'SV-221602' do
  title 'Splunk Enterprise must have all local user accounts removed after implementing organizational level user management system, except for one emergency account of last resort.'
  desc 'User accounts should use an organizational level authentication mechanism such as SAML, LDAP, AD, etc., to provide centralized management.

The use of local accounts should be discouraged, except for an emergency account of last resort.

The use of local accounts instead of organizational level accounts creates a risk where accounts are not properly disabled or deleted when users depart or their roles change.'
  desc 'check', 'Select Settings >> Access Controls >> Users. 

Verify that no user accounts exist with Authentication system set to Splunk except an account of last resort. They should all be set to LDAP or SAML.

If any user accounts have Authentication system set to Splunk, with the exception of one emergency account of last resort, this is a finding.'
  desc 'fix', 'Select Settings >> Access Controls >> Users. 

Delete any user account with Authentication system set to Splunk, with the exception of one emergency account of last resort. Splunk will prevent the user from deleting an LDAP account.'
  impact 0.7
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23317r416263_chk'
  tag severity: 'high'
  tag gid: 'V-221602'
  tag rid: 'SV-221602r879589_rule'
  tag stig_id: 'SPLK-CL-000030'
  tag gtitle: 'SRG-APP-000148-AU-002270'
  tag fix_id: 'F-23306r416264_fix'
  tag 'documentable'
  tag legacy: ['SV-111309', 'V-102353']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
