control 'SV-221609' do
  title 'Splunk Enterprise must use LDAPS for the LDAP connection.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Securing the connection to the LDAP servers mitigates this risk.'
  desc 'check', 'If the instance being checked is in a distributed environment and has the web interface disabled, this check is N/A.

If using SAML for authentication, this check is N/A.

Select Settings >> Access Controls >> Authentication method.

Select LDAP Settings.

Select the LDAP strategy and verify that SSL enabled is checked and the Port is set to 636.

If SSL enabled is not checked, and Port is not 636, this is a finding.'
  desc 'fix', 'If using SAML for authentication, this fix is N/A.

Select Settings >> Access Controls >> Authentication method.

Select LDAP Settings.

Select the LDAP strategy and check the option SSL enabled.

Set Port to 636.

Edit the following file in the installation to configure Splunk to use SSL certificates:

$SPLUNK_HOME/etc/openldap/ldap.conf

Add the following line:

TLS_CACERT <path to the DoD approved certificate in PEM format>'
  impact 0.7
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23324r663929_chk'
  tag severity: 'high'
  tag gid: 'V-221609'
  tag rid: 'SV-221609r879609_rule'
  tag stig_id: 'SPLK-CL-000080'
  tag gtitle: 'SRG-APP-000172-AU-002550'
  tag fix_id: 'F-23313r416285_fix'
  tag 'documentable'
  tag legacy: ['SV-111319', 'V-102367']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
