control 'SV-251000' do
  title 'The MobileIron Sentry must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk. A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network).'
  desc 'check', 'On the MobileIron Sentry console, do the following to verify FIPS mode is enabled: 

1. SSH to MobileIron Sentry Server from any SSH client.
2. Enter the administrator credentials set at MobileIron Sentry installation.
3. Enter "enable".
4. When prompted, enter the "enable secret" set at MobileIron Sentry installation. 
5. Enter "show FIPS".
6. Verify "FIPS 140 mode is enabled" is displayed. If it is not, this is a finding.

Then:
1. Log in to MobileIron Sentry.

2. Go to Settings >> SNMP. 

3. Verify SNMP server has been added.
a. If SNMP server is not added, this is a finding.
b.  If SNMP server is added, go to step 4. 

4. Verify SNMP Control is not disabled.
a. If SNMP Control is disabled, this is a finding.
b. If SNMP Control is not disabled, go to step 5.

5. Verify Protocol v3 is selected.
a. If Protocol v3 is not selected, this is a finding.
b. If Protocol v3 is selected, go to step 6.

6. Verify the SNMP v3 User has been added.
a. If SNMP v3 User has not been added, this is a finding.'
  desc 'fix', 'On MobileIron Sentry console, do the following to configure FIPS mode:

1. SSH to the MobileIron Sentry. 
2. At the prompt, enter "enable" mode with the secret credentials.
3. Type Configure command.
4. Type FIPS.
5. Once reloaded, SSH to the MobileIron Sentry.
6. Run the "show FIPS".

Then:
1. Log in to MobileIron Sentry.
2. Go to Settings >> SNMP.
3. Add SNMP Trap Receiver.
4. Enable SNMP Service.
5. Select Protocol v3.
6. Add SNMP v3 Users.
7. Enter User Name.
8. Select Security Level from dropdown.
9. Select AUTH Protocol from dropdown.
10. Enter AUTH Password.
11. Select Privacy Protocol from dropdown.
12. Enter Privacy Password.
13. Click "Save".
14. Enable Link Up/Down Trap.
15. Click "Apply" to save changes.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54435r802220_chk'
  tag severity: 'medium'
  tag gid: 'V-251000'
  tag rid: 'SV-251000r802222_rule'
  tag stig_id: 'MOIS-ND-000760'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-54389r802221_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
