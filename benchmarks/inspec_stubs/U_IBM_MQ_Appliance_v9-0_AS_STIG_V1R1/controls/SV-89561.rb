control 'SV-89561' do
  title 'The MQ Appliance messaging server must accept FICAM-approved third-party credentials.'
  desc 'Access may be denied to legitimate users if FICAM-approved third-party credentials are not accepted.

This requirement typically applies to organizational information systems that are accessible to non-federal government agencies and other partners. This allows federal government relying parties to trust such credentials at their approved assurance levels.

Third-party credentials are those credentials issued by non-federal government entities approved by the Federal Identity, Credential, and Access Management (FICAM) Trust Framework Solutions initiative.

'
  desc 'check', 'Log on to the WebGUI as a privileged user.

Click on the "MQ Console" icon.

Click "Add" widget at the top right of the screen.

Select queue manager intended for OCSP from the drop-down list.

Select "Authentication Information".

Verify that the authentication type is "OCSP".

Click on the "Properties" button.

Click "OCSP" on the side bar to verify that the OCSP responder URL is correct.

If either the authentication type is not "OCSP" or the OCSP responder URL in not correct, this is a finding.'
  desc 'fix', 'Log on to the WebGUI as a privileged user.

Click on the "MQ Console" icon.

Click "Add" widget at the top right of the screen.

Select a queue manager from the drop-down list.

Select "Authentication Information".

Click the "+" (plus sign) to define the authentication method authentication for this queue manager.

Specify an "Authinfo" name (e.g., USE.OCSP).

Select "OCSP" as the "Authinfo" type.

Specify an OCSP responder URL.

Click "Create".

In the "Local Queue Managers" widget, select the OCSP queue manager you just configured.

Click "More..." then select "Refresh Security... "'
  impact 0.3
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74745r1_chk'
  tag severity: 'low'
  tag gid: 'V-74887'
  tag rid: 'SV-89561r1_rule'
  tag stig_id: 'MQMH-AS-000840'
  tag gtitle: 'SRG-APP-000404-AS-000249'
  tag fix_id: 'F-81503r2_fix'
  tag satisfies: ['SRG-APP-000404-AS-000249', 'SRG-APP-000405-AS-000250']
  tag 'documentable'
  tag cci: ['CCI-002011', 'CCI-002014']
  tag nist: ['IA-8 (2)', 'IA-8 (4)']
end
